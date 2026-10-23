//! Port forwarding: local (`-L`), remote (`-R`) and dynamic (`-D`, our SOCKS5 server) forwards on
//! one SSH connection, every connection's bytes copied by [`pump`].
//!
//! [`ForwardSet`] is owned by the shell loop: one task per forward (listener or remote
//! listen request), one task per connection in that forward's `JoinSet`, so removing a forward
//! stops its connections too and the connection count is the set's length. Each forward
//! reports [`SessionOutput::ForwardStatus`]; listen addresses default to loopback and anything
//! else raises [`SessionWarning::ForwardExposed`]. Server-opened `forwarded-tcpip` channels are
//! only accepted for a port we asked the server to listen on.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fogu_core::{ForwardKind, PortForward};
use russh::client::{self, Handle};
use russh::{Channel, ChannelOpenFailure};
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use super::connect::Client;
use super::proxy::socks5::Target;
use super::proxy::socks5_server;
use crate::{
    ForwardCmd, ForwardId, ForwardState, ForwardStatus, SessionOutput, SessionWarning,
    sanitize_remote,
};

/// Incoming remote-forward channels queued per forward; more are rejected.
const INBOUND_QUEUE: usize = 16;
/// Deadline for a local program's SOCKS5 greeting + request.
const SOCKS_HANDSHAKE: Duration = Duration::from_secs(10);
/// Pause after a failed `accept` (e.g. out of file descriptors) before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// How long a forward may take to stop when the session ends.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// Longest error text reported to the UI.
const ERROR_MAX_CHARS: usize = 300;

/// Copies bytes both ways until both sides are done; logs the totals at debug.
pub(crate) async fn pump<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let totals = copy_bidirectional(a, b).await;
    match &totals {
        Ok((sent, received)) => tracing::debug!(sent, received, "forwarded connection closed"),
        Err(err) => tracing::debug!(error = %err, "forwarded connection failed"),
    }
    totals
}

/// A `forwarded-tcpip` channel the server opened (a connection to a remote forward).
pub(crate) struct Forwarded {
    pub(crate) channel: Channel<client::Msg>,
    /// The listen address the server reports.
    pub(crate) address: String,
    pub(crate) port: u32,
    /// Dropping it rejects the channel.
    pub(crate) reply: client::ChannelOpenHandle,
}

struct Running {
    id: ForwardId,
    forward: PortForward,
    stop: CancellationToken,
    task: JoinHandle<()>,
    inbound: Sender<Forwarded>,
}

/// The session's forwards.
pub(crate) struct ForwardSet {
    ssh: Arc<Handle<Client>>,
    out: Sender<SessionOutput>,
    next: u64,
    running: Vec<Running>,
}

impl ForwardSet {
    pub(crate) fn new(ssh: Arc<Handle<Client>>, out: Sender<SessionOutput>) -> Self {
        Self {
            ssh,
            out,
            next: 0,
            running: Vec::new(),
        }
    }

    pub(crate) fn command(&mut self, cmd: ForwardCmd) {
        match cmd {
            ForwardCmd::Add(forward) => self.add(forward),
            ForwardCmd::Remove(id) => self.remove(id),
        }
    }

    /// Starts `forward`; its task reports how that went.
    pub(crate) fn add(&mut self, forward: PortForward) {
        let id = ForwardId(self.next);
        self.next += 1;
        let stop = CancellationToken::new();
        let (inbound, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let ctx = Ctx {
            id,
            forward: forward.clone(),
            ssh: Arc::clone(&self.ssh),
            out: self.out.clone(),
        };
        let task = tokio::spawn(run(ctx, stop.clone(), inbound_rx).in_current_span());
        self.running.push(Running {
            id,
            forward,
            stop,
            task,
            inbound,
        });
    }

    /// Stops a forward; its task reports `Stopped` once its connections are closed.
    fn remove(&mut self, id: ForwardId) {
        if let Some(at) = self.running.iter().position(|r| r.id == id) {
            self.running.swap_remove(at).stop.cancel();
        }
    }

    /// Hands a server-opened channel to the remote forward listening on its port (same
    /// address preferred); without one the channel is rejected.
    pub(crate) fn route(&self, incoming: Forwarded) {
        let remote = || {
            self.running.iter().filter(|r| {
                r.forward.kind == ForwardKind::Remote && u32::from(r.forward.port) == incoming.port
            })
        };
        let target = remote()
            .find(|r| r.forward.bind_host() == incoming.address)
            .or_else(|| remote().next());
        let Some(running) = target else {
            tracing::debug!(
                port = incoming.port,
                "forwarded-tcpip channel for a port we don't forward; rejected"
            );
            return;
        };
        if running.inbound.try_send(incoming).is_err() {
            tracing::debug!("remote forward busy; channel rejected");
        }
    }

    /// Stops every forward (session end) and waits for them, bounded.
    pub(crate) async fn stop(self) {
        for running in &self.running {
            running.stop.cancel();
        }
        for running in self.running {
            if tokio::time::timeout(STOP_GRACE, running.task)
                .await
                .is_err()
            {
                tracing::warn!(id = running.id.0, "port forward did not stop in time");
            }
        }
    }
}

/// What a forward's task needs.
struct Ctx {
    id: ForwardId,
    forward: PortForward,
    ssh: Arc<Handle<Client>>,
    out: Sender<SessionOutput>,
}

impl Ctx {
    async fn report(&self, state: ForwardState, active_connections: usize) {
        let status = ForwardStatus {
            id: self.id,
            forward: self.forward.clone(),
            state,
            active_connections,
        };
        // The UI may be gone (closing): nothing left to tell.
        let _gone = self.out.send(SessionOutput::ForwardStatus(status)).await;
    }

    /// The listener is up: warn when other machines can reach it, then report `Listening`.
    async fn started(&self) {
        let label = sanitize_remote(&self.forward.label(), ERROR_MAX_CHARS, false);
        tracing::info!(forward = %label, "port forward listening");
        if self.forward.is_exposed() {
            tracing::warn!(forward = %label, "port forward reachable from other machines");
            let warning = SessionWarning::ForwardExposed(label);
            let _gone = self.out.send(SessionOutput::Warning(warning)).await;
        }
        self.report(ForwardState::Listening, 0).await;
    }
}

/// One forward's whole life: start, serve until stopped (or report why it can't), `Stopped`.
async fn run(ctx: Ctx, stop: CancellationToken, inbound: Receiver<Forwarded>) {
    let result = match (ctx.forward.problem(), ctx.forward.kind) {
        (Some(problem), _) => Err(problem.to_owned()),
        (None, ForwardKind::Remote) => remote(&ctx, &stop, inbound).await,
        (None, ForwardKind::Local | ForwardKind::Dynamic) => local(&ctx, &stop).await,
    };
    if let Err(err) = result {
        let err = sanitize_remote(&err, ERROR_MAX_CHARS, false);
        tracing::warn!(error = %err, "port forward failed");
        ctx.report(ForwardState::Error(err), 0).await;
        stop.cancelled().await;
    }
    ctx.report(ForwardState::Stopped, 0).await;
}

/// `-L` / `-D`: a local listener, each connection through a `direct-tcpip` channel.
async fn local(ctx: &Ctx, stop: &CancellationToken) -> Result<(), String> {
    let (host, port) = (ctx.forward.bind_host(), ctx.forward.port);
    let listener = TcpListener::bind((host, port))
        .await
        .map_err(|err| match err.kind() {
            // Kept under the dialog's 120 shown characters.
            std::io::ErrorKind::AddrInUse => format!(
                "port {port} on {host} is in use (another program, ssh or tab); only this forward \
                 is off"
            ),
            _ => format!("cannot listen on {host}:{port}: {err}"),
        })?;
    ctx.started().await;
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            () = stop.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((socket, peer)) => {
                    let ssh = Arc::clone(&ctx.ssh);
                    if ctx.forward.kind == ForwardKind::Dynamic {
                        conns.spawn(socks(ssh, socket, peer).in_current_span());
                    } else {
                        let target = Target::Name(ctx.forward.target_address.clone(), ctx.forward.target_port);
                        conns.spawn(direct(ssh, socket, peer, target).in_current_span());
                    }
                    ctx.report(ForwardState::Listening, conns.len()).await;
                }
                Err(err) => {
                    tracing::debug!(error = %err, "accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            Some(_done) = conns.join_next() => ctx.report(ForwardState::Listening, conns.len()).await,
        }
    }
    conns.shutdown().await;
    Ok(())
}

/// Opens `direct-tcpip` to `target` for the local connection from `peer`.
async fn open_direct(
    ssh: &Handle<Client>,
    peer: SocketAddr,
    target: &Target,
) -> Result<Channel<client::Msg>, russh::Error> {
    let (host, port) = match target {
        Target::Name(host, port) => (host.clone(), *port),
        Target::Addr(ip, port) => (ip.to_string(), *port),
    };
    ssh.channel_open_direct_tcpip(
        host,
        u32::from(port),
        peer.ip().to_string(),
        u32::from(peer.port()),
    )
    .await
}

async fn direct(ssh: Arc<Handle<Client>>, mut socket: TcpStream, peer: SocketAddr, target: Target) {
    match open_direct(&ssh, peer, &target).await {
        Ok(channel) => {
            let _done = pump(&mut socket, &mut channel.into_stream()).await;
        }
        Err(err) => {
            let error = sanitize_remote(&err.to_string(), ERROR_MAX_CHARS, false);
            tracing::info!(%error, "the server refused the forwarded connection");
        }
    }
}

async fn socks(ssh: Arc<Handle<Client>>, mut socket: TcpStream, peer: SocketAddr) {
    let target =
        match tokio::time::timeout(SOCKS_HANDSHAKE, socks5_server::accept(&mut socket)).await {
            Ok(Ok(target)) => target,
            Ok(Err(err)) => {
                let error = sanitize_remote(&err, ERROR_MAX_CHARS, false);
                tracing::debug!(%error, "SOCKS5 handshake refused");
                return;
            }
            Err(_elapsed) => {
                tracing::debug!("SOCKS5 handshake timed out");
                return;
            }
        };
    match open_direct(&ssh, peer, &target).await {
        Ok(channel) => {
            if socks5_server::reply(&mut socket, socks5_server::SUCCEEDED)
                .await
                .is_ok()
            {
                let _done = pump(&mut socket, &mut channel.into_stream()).await;
            }
        }
        Err(err) => {
            let error = sanitize_remote(&err.to_string(), ERROR_MAX_CHARS, false);
            tracing::info!(%error, "the server refused the SOCKS connection");
            let _gone = socks5_server::reply(&mut socket, socks5_server::GENERAL_FAILURE).await;
        }
    }
}

/// `-R`: asks the server to listen; its `forwarded-tcpip` channels connect to the target from
/// here. Cancelled on the server when stopped.
async fn remote(
    ctx: &Ctx,
    stop: &CancellationToken,
    mut inbound: Receiver<Forwarded>,
) -> Result<(), String> {
    let (host, port) = (ctx.forward.bind_host().to_owned(), ctx.forward.port);
    let request = ctx.ssh.tcpip_forward(host.clone(), u32::from(port));
    let listening = tokio::select! {
        result = request => result,
        () = stop.cancelled() => return Ok(()),
    };
    match listening {
        Ok(_port) => {}
        Err(russh::Error::RequestDenied) => {
            return Err(format!(
                "the server refused to listen on {host}:{port} (port in use or forwarding not allowed)"
            ));
        }
        Err(err) => return Err(format!("remote listen on {host}:{port} failed: {err}")),
    }
    ctx.started().await;
    let target = (ctx.forward.target_address.clone(), ctx.forward.target_port);
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            () = stop.cancelled() => break,
            incoming = inbound.recv() => match incoming {
                Some(incoming) => {
                    conns.spawn(connect_back(incoming, target.clone()).in_current_span());
                    ctx.report(ForwardState::Listening, conns.len()).await;
                }
                // The set dropped this forward: it was removed.
                None => break,
            },
            Some(_done) = conns.join_next() => ctx.report(ForwardState::Listening, conns.len()).await,
        }
    }
    conns.shutdown().await;
    if let Err(err) = ctx.ssh.cancel_tcpip_forward(host, u32::from(port)).await {
        tracing::debug!(error = %err, "cancel-tcpip-forward failed");
    }
    Ok(())
}

/// Connects to the local target, then accepts the server's channel (or rejects it).
async fn connect_back(incoming: Forwarded, (host, port): (String, u16)) {
    match TcpStream::connect((host.as_str(), port)).await {
        Ok(mut socket) => {
            incoming.reply.accept().await;
            let _done = pump(&mut socket, &mut incoming.channel.into_stream()).await;
        }
        Err(err) => {
            tracing::info!(error = %err, "remote forward target unreachable");
            incoming
                .reply
                .reject(ChannelOpenFailure::ConnectFailed)
                .await;
        }
    }
}

#[cfg(test)]
mod tests {

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    use super::pump;

    #[tokio::test]
    async fn pump_copies_both_ways_and_counts() {
        let (mut a, mut a_far) = duplex(64);
        let (mut b, mut b_far) = duplex(64);
        let copier = tokio::spawn(async move { pump(&mut a, &mut b).await });
        a_far.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        b_far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        b_far.write_all(b"pong!").await.unwrap();
        let mut got = [0u8; 5];
        a_far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong!");
        drop((a_far, b_far));
        assert_eq!(copier.await.unwrap().unwrap(), (4, 5));
    }
}
