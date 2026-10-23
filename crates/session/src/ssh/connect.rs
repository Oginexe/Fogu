//! Transport (`transport.rs`) + SSH handshake with strict host-key verification: an unknown or
//! changed key never connects without the user's explicit approval.
//!
//! russh calls [`Client::check_server_key`] inside its connection future; the handler forwards
//! the key to [`connect`], which drives that future and answers from `known_hosts` or a prompt
//! (awaited on the session's own input channel, never blocking a worker). After the first accepted
//! key, re-key exchanges must present the same key or are refused without asking.

use std::borrow::Cow;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fogu_core::EffectiveSsh;
use russh::client;
use russh::keys::{Algorithm, PublicKey, PublicKeyOrCertificate};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep_until};
use tracing::Instrument as _;

use super::forward::Forwarded;
use super::hostkeys::{self, Lookup};
use super::transport::{self, Route};
use super::x11::X11Fwd;
use super::{SshPaths, Stop, Ui, agent, algorithms};
use crate::{HostKeyFailure, PromptKind, PromptReply, SessionError, SessionOutput, SessionWarning};

/// Messages from the russh handler (running inside russh's session task) to our task.
pub(crate) enum HandlerEvent {
    /// Decide on this server key; answer `true` to accept.
    HostKey(Box<PublicKey>, oneshot::Sender<bool>),
    /// The server's auth banner (raw; sanitized when shown).
    Banner(String),
}

/// Server-opened `forwarded-tcpip` channels waiting for the session (remote forwards).
const FORWARDED_QUEUE: usize = 16;

/// Our russh client handler.
pub(crate) struct Client {
    events: mpsc::Sender<HandlerEvent>,
    /// Incoming remote-forward connections, routed by the shell loop; a full queue (or one
    /// nobody reads, e.g. a jump host's) rejects the channel.
    forwarded: mpsc::Sender<Forwarded>,
    /// The key accepted for this connection; re-keys must match it.
    accepted: Option<PublicKey>,
    /// Agent socket for `auth-agent@openssh.com` channels; `None` = agent forwarding is off
    /// and such channels are rejected.
    agent: Option<PathBuf>,
    /// X11 forwarding state; `None` = `x11` channels are rejected.
    x11: Option<Arc<X11Fwd>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            // We never advertise certificate host-key algorithms; refuse one if sent anyway.
            tracing::warn!("server presented a host certificate; refused");
            return Ok(false);
        };
        if let Some(accepted) = &self.accepted {
            let same = accepted.key_data() == key.key_data();
            if !same {
                tracing::warn!("host key changed during re-key; disconnecting");
            }
            return Ok(same);
        }
        let (tx, rx) = oneshot::channel();
        if self
            .events
            .send(HandlerEvent::HostKey(Box::new(key.clone()), tx))
            .await
            .is_err()
        {
            return Ok(false);
        }
        let ok = rx.await.unwrap_or(false);
        if ok {
            self.accepted = Some(key.clone());
        }
        Ok(ok)
    }

    fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        // Dropped if our task is busy and the queue is full: a banner is informational.
        let _full = self
            .events
            .try_send(HandlerEvent::Banner(banner.to_owned()));
        std::future::ready(Ok(()))
    }

    fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let incoming = Forwarded {
            channel,
            address: connected_address.to_owned(),
            port: connected_port,
            reply,
        };
        // Dropping the handle (queue full or closed) rejects the channel.
        if self.forwarded.try_send(incoming).is_err() {
            tracing::debug!("forwarded-tcpip channel rejected (not listening)");
        }
        std::future::ready(Ok(()))
    }

    fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        match self.agent.clone() {
            Some(socket) => {
                let serve = async move { agent::serve_forward(channel, reply, &socket).await };
                tokio::spawn(serve.in_current_span());
            }
            // Dropping the handle rejects: we never asked for agent forwarding.
            None => {
                tracing::warn!("agent channel opened by the server without forwarding; rejected");
            }
        }
        std::future::ready(Ok(()))
    }

    fn server_channel_open_x11(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        if let Some(x11) = self.x11.clone() {
            let serve = async move {
                reply.accept().await;
                super::x11::serve(channel.into_stream(), &x11).await;
            };
            tokio::spawn(serve.in_current_span());
        } else {
            tracing::warn!("X11 channel opened by the server without forwarding; rejected");
        }
        std::future::ready(Ok(()))
    }
}

/// An established, not yet authenticated connection.
pub(crate) struct Connection {
    pub(crate) handle: client::Handle<Client>,
    /// Banners (and refused late host-key checks) arriving after the handshake.
    pub(crate) events: mpsc::Receiver<HandlerEvent>,
    /// Server-opened remote-forward channels (see [`Client`]).
    pub(crate) forwarded: mpsc::Receiver<Forwarded>,
    /// Request agent forwarding on each shell channel (an agent was found).
    pub(crate) agent_forward: bool,
    /// Request X11 forwarding (`x11-req`) on each shell channel with this fake cookie.
    pub(crate) x11: Option<Arc<X11Fwd>>,
    /// The jump host connection / proxy command under this one; declared last, so it is
    /// dropped (closed) after `handle`.
    pub(crate) route: Route,
}

impl Connection {
    /// Shows queued banners (unless `skip_banner`); answers any late host-key check with "no".
    pub(crate) async fn drain_events(
        &mut self,
        ssh: &EffectiveSsh,
        ui: &mut Ui,
    ) -> Result<(), Stop> {
        while let Ok(event) = self.events.try_recv() {
            handle_late_event(event, ssh, ui).await?;
        }
        Ok(())
    }
}

async fn handle_late_event(
    event: HandlerEvent,
    ssh: &EffectiveSsh,
    ui: &mut Ui,
) -> Result<(), Stop> {
    match event {
        HandlerEvent::Banner(text) if !ssh.skip_banner => ui.banner(&text).await?,
        HandlerEvent::Banner(_) => {}
        HandlerEvent::HostKey(_, reply) => {
            let _closed = reply.send(false);
        }
    }
    Ok(())
}

/// Connects to `ssh.host:ssh.port` along the profile's route, verifying the host key.
/// `ready` bounds each network step (time spent waiting for the user's answers is not
/// counted). `depth` = jump hosts already on the way.
pub(crate) async fn connect(
    ssh: &EffectiveSsh,
    paths: &SshPaths,
    ui: &mut Ui,
    ready: Duration,
    depth: usize,
) -> Result<Connection, Stop> {
    if ssh.host.is_empty() {
        return Err(SessionError::NoHost.into());
    }
    let problems = ssh.route_problems();
    if !problems.is_empty() {
        let text = crate::sanitize_remote(&problems.join("; "), 300, false);
        return Err(SessionError::Route(text).into());
    }
    ui.service(&format!(
        "Connecting to {}:{}{}…",
        ssh.host,
        ssh.port,
        transport::describe(ssh)
    ))
    .await?;
    let (stream, mut route) = transport::open(ssh, paths, ui, ready, depth).await?;
    let files = paths.files();
    let (kh_host, kh_port) = known_hosts_name(ssh);
    let preferred = checked_algorithms(ssh, ui).await?;
    let config = Arc::new(config(
        ssh,
        preferred,
        &hostkeys::known_algorithms(&files, kh_host, kh_port),
    ));
    let (agent, x11) = if depth == 0 {
        forwarding(ssh, ui).await?
    } else {
        (None, None)
    };
    let (tx, mut events) = mpsc::channel(8);
    let (forwarded_tx, forwarded) = mpsc::channel(FORWARDED_QUEUE);
    let agent_forward = agent.is_some();
    let handler = Client {
        events: tx,
        forwarded: forwarded_tx,
        accepted: None,
        agent,
        x11: x11.clone(),
    };
    let fut = client::connect_stream(config, stream, handler);
    tokio::pin!(fut);
    let mut deadline = Instant::now() + ready;
    let mut refused: Option<HostKeyFailure> = None;
    loop {
        tokio::select! {
            result = &mut fut => {
                return match result {
                    Ok(handle) => Ok(Connection {
                        handle,
                        events,
                        forwarded,
                        agent_forward,
                        x11,
                        route,
                    }),
                    Err(err) => {
                        let proxy = match refused {
                            None => route.proxy_failure().await,
                            Some(_) => None,
                        };
                        Err(proxy.unwrap_or_else(|| connect_error(err, refused, ssh)).into())
                    }
                };
            }
            Some(event) = events.recv() => match event {
                HandlerEvent::HostKey(key, reply) => {
                    let started = Instant::now();
                    let verdict = verify(ssh, paths, ui, &key).await;
                    deadline += started.elapsed();
                    match verdict {
                        Ok(()) => {
                            let _closed = reply.send(true);
                        }
                        Err(Stop::Failed(SessionError::HostKey(failure))) => {
                            refused = Some(failure);
                            let _closed = reply.send(false);
                        }
                        Err(stop) => return Err(stop),
                    }
                }
                banner @ HandlerEvent::Banner(_) => handle_late_event(banner, ssh, ui).await?,
            },
            input = ui.in_rx.recv() => ui.idle_input(input.as_ref())?,
            () = sleep_until(deadline) => {
                let proxy = route.proxy_failure().await;
                return Err(proxy.unwrap_or(SessionError::Timeout).into());
            }
        }
    }
}

/// [`connect`] boxed, for the jump-host recursion (`transport` → `connect` → `transport`).
pub(crate) fn connect_boxed<'a>(
    ssh: &'a EffectiveSsh,
    paths: &'a SshPaths,
    ui: &'a mut Ui,
    ready: Duration,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<Connection, Stop>> + Send + 'a>> {
    Box::pin(connect(ssh, paths, ui, ready, depth))
}

/// The profile's algorithm lists as russh preferences; unknown names (ignored) and names
/// outside russh's defaults are shown and reported as warnings.
async fn checked_algorithms(ssh: &EffectiveSsh, ui: &mut Ui) -> Result<russh::Preferred, Stop> {
    let mapped = algorithms::preferred(&ssh.algorithms);
    if !mapped.unknown.is_empty() {
        let list = mapped.unknown.join(", ");
        ui.service(&format!("Unknown algorithms ignored: {list}"))
            .await?;
        ui.pump
            .emit(SessionOutput::Warning(SessionWarning::UnknownAlgorithms(
                mapped.unknown,
            )))
            .await?;
    }
    if !mapped.weak.is_empty() {
        let list = mapped.weak.join(", ");
        tracing::warn!(algorithms = %list, "algorithms outside the defaults enabled");
        ui.service(&format!(
            "Weaker algorithms enabled by this profile: {list}"
        ))
        .await?;
        ui.pump
            .emit(SessionOutput::Warning(SessionWarning::WeakAlgorithms(
                mapped.weak,
            )))
            .await?;
    }
    Ok(mapped.preferred)
}

/// Agent socket and X11 state for the target connection, when the profile asks for them;
/// why one can't be forwarded is shown and the connection goes on without it.
async fn forwarding(
    ssh: &EffectiveSsh,
    ui: &mut Ui,
) -> Result<(Option<PathBuf>, Option<Arc<X11Fwd>>), Stop> {
    let mut agent_socket = None;
    if ssh.agent_forward {
        match agent::find(ssh.agent_path.as_deref()).await {
            Some((socket, _agent)) => agent_socket = Some(socket),
            None => {
                ui.service("Agent forwarding off: no SSH agent found")
                    .await?;
            }
        }
    }
    let mut x11 = None;
    if ssh.x11 {
        match X11Fwd::from_env() {
            Ok(fwd) => x11 = Some(Arc::new(fwd)),
            Err(why) => ui.service(&format!("X11 forwarding off: {why}")).await?,
        }
    }
    Ok((agent_socket, x11))
}

/// The transport config: keepalives from the profile, `TCP_NODELAY`, the profile's algorithm
/// preferences, and the host-key algorithms we already have records for moved to the front
/// (OpenSSH does the same), so a server with several host keys presents the one we know
/// instead of a false "changed".
fn config(
    ssh: &EffectiveSsh,
    mut preferred: russh::Preferred,
    known: &[Algorithm],
) -> client::Config {
    if !known.is_empty() {
        let is_known = |alg: &Algorithm| {
            known.iter().any(|k| {
                k == alg || matches!((k, alg), (Algorithm::Rsa { .. }, Algorithm::Rsa { .. }))
            })
        };
        let mut keys = preferred.key.to_vec();
        keys.sort_by_key(|alg| !is_known(alg));
        preferred.key = Cow::Owned(keys);
    }
    client::Config {
        keepalive_interval: ssh.keepalive_interval,
        keepalive_max: ssh.keepalive_count_max as usize,
        nodelay: true,
        preferred,
        ..client::Config::default()
    }
}

/// Maps a failed handshake: a refused key reports why we refused it, an ended proxy command
/// what it said.
fn connect_error(
    err: russh::Error,
    refused: Option<HostKeyFailure>,
    ssh: &EffectiveSsh,
) -> SessionError {
    match (err, refused) {
        (_, Some(failure)) => SessionError::HostKey(failure),
        (russh::Error::IO(source), None) => SessionError::Connect {
            target: crate::sanitize_remote(&format!("{}:{}", ssh.host, ssh.port), 300, false),
            source: Arc::new(source),
        },
        (russh::Error::UnknownKey, None) => SessionError::HostKey(HostKeyFailure::Certificate),
        (err, None) => ssh_error(&err),
    }
}

/// Any other russh error as sanitized text (some variants quote server-sent names).
pub(crate) fn ssh_error(err: &dyn std::fmt::Display) -> SessionError {
    SessionError::Ssh(crate::sanitize_remote(&err.to_string(), 300, false))
}

/// Decides on `key`: `known_hosts`, else a prompt. `Err(HostKey(..))` = refuse.
async fn verify(
    ssh: &EffectiveSsh,
    paths: &SshPaths,
    ui: &mut Ui,
    key: &PublicKey,
) -> Result<(), Stop> {
    let fingerprint = hostkeys::fingerprint(key);
    let key_type = key.algorithm().as_str().to_owned();
    if !ssh.verify_host_keys {
        tracing::warn!(%fingerprint, "host key NOT verified (verify_host_keys = false)");
        ui.service(&format!(
            "Host key NOT verified (verify_host_keys = false): {key_type} {fingerprint}"
        ))
        .await?;
        ui.pump
            .emit(SessionOutput::Warning(SessionWarning::HostKeyNotVerified))
            .await?;
        return Ok(());
    }
    let refuse = |failure| Err(Stop::Failed(SessionError::HostKey(failure)));
    let (kh_host, kh_port) = known_hosts_name(ssh);
    match hostkeys::lookup(&paths.files(), kh_host, kh_port, key) {
        Lookup::Known => Ok(()),
        Lookup::Revoked { path, line } => {
            tracing::warn!(path = %path.display(), line, "revoked host key offered");
            refuse(HostKeyFailure::Revoked)
        }
        Lookup::Unknown => {
            let kind = PromptKind::HostKeyUnknown {
                host: ssh.host.clone(),
                port: ssh.port,
                key_type,
                fingerprint,
            };
            match ui.ask(kind).await? {
                PromptReply::Accept => Ok(()),
                PromptReply::AcceptAndSave => {
                    if let Err(err) = hostkeys::learn(&paths.known_hosts, kh_host, kh_port, key) {
                        tracing::warn!(error = %err, "could not save the host key");
                        ui.service(&format!(
                            "Could not save the host key in {}: {err}",
                            paths.known_hosts.display()
                        ))
                        .await?;
                    }
                    Ok(())
                }
                _ => refuse(HostKeyFailure::Rejected),
            }
        }
        Lookup::Changed { path, line, old } => {
            tracing::warn!(path = %path.display(), line, %fingerprint, "HOST KEY CHANGED");
            ui.service(&format!(
                "WARNING: the host key of {}:{} has CHANGED ({}:{line}). Someone could be \
                 eavesdropping on you (man-in-the-middle attack).",
                ssh.host,
                ssh.port,
                path.display()
            ))
            .await?;
            let kind = PromptKind::HostKeyChanged {
                host: ssh.host.clone(),
                port: ssh.port,
                key_type,
                fingerprint,
                old_fingerprint: hostkeys::fingerprint(&old),
                known_hosts_path: path,
                line,
            };
            // Only the explicit replace flow continues; a plain Accept is a refusal.
            match ui.ask(kind).await? {
                PromptReply::AcceptAndSave => {
                    match hostkeys::replace(&paths.known_hosts, kh_host, kh_port, key) {
                        Ok(()) => Ok(()),
                        Err(err) => {
                            tracing::warn!(error = %err, "could not replace the host key");
                            ui.service(&format!(
                                "Could not replace the host key in {}: {err}",
                                paths.known_hosts.display()
                            ))
                            .await?;
                            refuse(HostKeyFailure::Changed)
                        }
                    }
                }
                _ => refuse(HostKeyFailure::Changed),
            }
        }
    }
}

/// The `known_hosts` name of the server: `host_key_alias` as is (OpenSSH appends no port to an
/// alias), else host and port.
fn known_hosts_name(ssh: &EffectiveSsh) -> (&str, u16) {
    ssh.host_key_alias
        .as_deref()
        .map_or((ssh.host.as_str(), ssh.port), |alias| (alias, 22))
}
