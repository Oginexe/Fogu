//! One SSH connection, many tabs (`reuse_session`): every authenticated connection is driven by one
//! task ([`start`]) that owns what belongs to the connection rather than to a tab — the jump-host
//! route, late handler events, the port forwards (profile forwards start once per connection,
//! [`ForwardSet`]) and the server-opened remote-forward channels. Tabs hold a [`Lease`]: they open
//! their own shell (and SFTP) channels on the shared handle and get every forward status fanned out
//! to them.
//!
//! [`ConnectionPool`] finds a live connection by profile id **and** the whole resolved profile
//! (user, route, algorithms, forwarding…), so nothing is shared across profiles or settings.
//! The last lease dropped starts the profile's `reuse_linger`; when it runs out unused, the
//! connection leaves the pool and closes. A dropped connection leaves the pool at once and
//! cancels [`Shared::gone`], which ends every tab on it.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fogu_core::{EffectiveSsh, ProfileId};
use russh::Disconnect;
use russh::client::Handle;
use tokio::sync::mpsc::{self, Sender, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use super::connect::{Client, Connection, HandlerEvent};
use super::forward::ForwardSet;
use super::x11::X11Fwd;
use crate::{ConnectionId, ForwardCmd, ForwardState, ForwardStatus, SessionOutput};

/// Forward status/warning queue between the [`ForwardSet`] and the fan-out.
const FANOUT_QUEUE: usize = 64;

/// What makes two tabs share a connection: the profile and everything it resolved to.
pub(crate) type Key = (ProfileId, EffectiveSsh);

/// The pooled connections.
type Live = Vec<(Key, Arc<Shared>)>;

/// The pool key of `ssh` opened from `profile` (per-pane choices left out).
pub(crate) fn key(profile: ProfileId, ssh: &EffectiveSsh) -> Key {
    let mut ssh = ssh.clone();
    ssh.clear_service_messages_on_connect = true;
    // Typed into the new shell only: a split/reconnect with `remember_cwd` still shares.
    ssh.cwd = None;
    (profile, ssh)
}

/// Live SSH connections that new tabs of the same profile can reuse. Cheap to clone; owned by
/// the [`SessionRuntime`](crate::SessionRuntime).
#[derive(Clone, Default)]
pub struct ConnectionPool {
    live: Arc<Mutex<Live>>,
}

impl std::fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPool")
            .field("connections", &self.lock().len())
            .finish()
    }
}

impl ConnectionPool {
    fn lock(&self) -> std::sync::MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A lease on the live connection for `key`, if there is one; `out` gets its forwards.
    pub(crate) fn lease(&self, key: &Key, out: Sender<SessionOutput>) -> Option<Lease> {
        let live = self.lock();
        let (_, shared) = live
            .iter()
            .find(|(k, s)| k == key && !s.gone.is_cancelled())?;
        Some(Lease::new(Arc::clone(shared), out))
    }

    /// Number of pooled connections (tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }
}

/// Where a connection is registered (absent = not shared).
pub(crate) struct Pooled {
    pub(crate) pool: ConnectionPool,
    pub(crate) profile: ProfileId,
}

/// One connection, shared by its leases.
pub(crate) struct Shared {
    pub(crate) id: ConnectionId,
    pub(crate) handle: Arc<Handle<Client>>,
    /// Request agent forwarding on each shell channel.
    pub(crate) agent_forward: bool,
    /// Request X11 forwarding on each shell channel.
    pub(crate) x11: Option<Arc<X11Fwd>>,
    /// Cancelled once the connection is gone (dropped by the server/network or closed).
    pub(crate) gone: CancellationToken,
    /// Leases alive; changed up only under the pool lock (or before the connection is pooled).
    refs: AtomicUsize,
    cmds: UnboundedSender<Cmd>,
}

enum Cmd {
    Attach(u64, Sender<SessionOutput>),
    Release(u64),
    Forward(ForwardCmd),
}

/// A tab's hold on a connection; dropping it releases the connection.
pub(crate) struct Lease {
    shared: Arc<Shared>,
    id: u64,
}

impl Lease {
    fn new(shared: Arc<Shared>, out: Sender<SessionOutput>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        shared.refs.fetch_add(1, Ordering::SeqCst);
        let _closed = shared.cmds.send(Cmd::Attach(id, out));
        Self { shared, id }
    }

    pub(crate) fn shared(&self) -> &Shared {
        &self.shared
    }

    /// Adds or removes a forward of the connection.
    pub(crate) fn forward(&self, cmd: ForwardCmd) {
        let _closed = self.shared.cmds.send(Cmd::Forward(cmd));
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.shared.refs.fetch_sub(1, Ordering::SeqCst);
        let _closed = self.shared.cmds.send(Cmd::Release(self.id));
    }
}

/// Takes over an authenticated connection: starts its driver task (and the profile's forwards),
/// registers it in `pooled` (unless a live one for the same key got there first) and returns
/// the first lease plus the driver's handle.
pub(crate) fn start(
    conn: Connection,
    ssh: &EffectiveSsh,
    pooled: Option<Pooled>,
    out: Sender<SessionOutput>,
) -> (Lease, JoinHandle<()>) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // Unbounded is fine: commands come one per user action (open a pane, add a forward, close).
    let (cmds, cmds_rx) = mpsc::unbounded_channel();
    let handle = Arc::new(conn.handle);
    let shared = Arc::new(Shared {
        id: ConnectionId(NEXT.fetch_add(1, Ordering::Relaxed)),
        handle: Arc::clone(&handle),
        agent_forward: conn.agent_forward,
        x11: conn.x11,
        gone: CancellationToken::new(),
        refs: AtomicUsize::new(0),
        cmds,
    });
    let lease = Lease::new(Arc::clone(&shared), out);
    let (fan_tx, fan_rx) = mpsc::channel(FANOUT_QUEUE);
    let mut forwards = ForwardSet::new(handle, fan_tx);
    for forward in &ssh.forwarded_ports {
        forwards.add(forward.clone());
    }
    let registered = pooled.map(|Pooled { pool, profile }| {
        let key = key(profile, ssh);
        let mut live = pool.lock();
        live.retain(|(_, s)| !s.gone.is_cancelled());
        if !live.iter().any(|(k, _)| *k == key) {
            live.push((key, Arc::clone(&shared)));
        }
        drop(live);
        pool
    });
    let linger = if registered.is_some() {
        ssh.reuse_linger
    } else {
        Duration::ZERO
    };
    let driver = Driver {
        shared,
        pool: registered,
        linger,
        subscribers: Vec::new(),
        statuses: Vec::new(),
        warnings: Vec::new(),
    };
    let ends = Ends {
        cmds: cmds_rx,
        fan: fan_rx,
        events: conn.events,
        forwarded: conn.forwarded,
    };
    let task = tokio::spawn(
        driver
            .run(ends, forwards, conn.route)
            .instrument(tracing::Span::current()),
    );
    (lease, task)
}

/// The receiving ends the driver selects on.
struct Ends {
    cmds: mpsc::UnboundedReceiver<Cmd>,
    fan: mpsc::Receiver<SessionOutput>,
    events: mpsc::Receiver<HandlerEvent>,
    forwarded: mpsc::Receiver<super::forward::Forwarded>,
}

struct Driver {
    shared: Arc<Shared>,
    pool: Option<ConnectionPool>,
    linger: Duration,
    subscribers: Vec<(u64, Sender<SessionOutput>)>,
    /// Last status of each forward that hasn't stopped (replayed to new leases).
    statuses: Vec<ForwardStatus>,
    /// Forward warnings so far (replayed to new leases).
    warnings: Vec<SessionOutput>,
}

impl Driver {
    async fn run(
        mut self,
        mut ends: Ends,
        mut forwards: ForwardSet,
        route: super::transport::Route,
    ) {
        let mut retire_at: Option<Instant> = None;
        loop {
            tokio::select! {
                Some(cmd) = ends.cmds.recv() => match cmd {
                    Cmd::Attach(id, out) => {
                        retire_at = None;
                        self.attach(id, out).await;
                    }
                    Cmd::Release(id) => {
                        // An unshared connection's one tab waits for it to close and gets the
                        // final forward statuses; a pooled tab stops listening when it leaves.
                        if self.pool.is_some() {
                            self.subscribers.retain(|(sub, _)| *sub != id);
                        }
                        if self.shared.refs.load(Ordering::SeqCst) == 0 {
                            retire_at = Some(Instant::now() + self.linger);
                        }
                    }
                    Cmd::Forward(cmd) => forwards.command(cmd),
                },
                Some(out) = ends.fan.recv() => self.fan_out(out).await,
                Some(incoming) = ends.forwarded.recv() => forwards.route(incoming),
                event = ends.events.recv() => match event {
                    // The handler is gone: so is the connection.
                    None => {
                        tracing::info!("SSH connection closed");
                        break;
                    }
                    Some(HandlerEvent::HostKey(_, reply)) => {
                        let _closed = reply.send(false);
                    }
                    Some(HandlerEvent::Banner(_)) => {}
                },
                () = sleep_until(retire_at.unwrap_or_else(Instant::now)), if retire_at.is_some() => {
                    retire_at = None;
                    if self.retire() {
                        break;
                    }
                }
            }
        }
        self.leave_pool();
        self.shared.gone.cancel();
        forwards.stop().await;
        while let Ok(out) = ends.fan.try_recv() {
            self.fan_out(out).await;
        }
        let _bye = self
            .shared
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        route.close().await;
    }

    /// `true` when no lease is left: the connection leaves the pool (under its lock, so no new
    /// lease can appear) and closes.
    fn retire(&self) -> bool {
        let Some(pool) = &self.pool else {
            return self.shared.refs.load(Ordering::SeqCst) == 0;
        };
        let mut live = pool.lock();
        if self.shared.refs.load(Ordering::SeqCst) > 0 {
            return false;
        }
        live.retain(|(_, s)| !Arc::ptr_eq(s, &self.shared));
        true
    }

    fn leave_pool(&self) {
        if let Some(pool) = &self.pool {
            pool.lock().retain(|(_, s)| !Arc::ptr_eq(s, &self.shared));
        }
    }

    /// A new lease: tell it which connection it is on and replay the forwards.
    async fn attach(&mut self, id: u64, out: Sender<SessionOutput>) {
        let replay = std::iter::once(SessionOutput::Connection(self.shared.id))
            .chain(self.warnings.iter().cloned())
            .chain(
                self.statuses
                    .iter()
                    .cloned()
                    .map(SessionOutput::ForwardStatus),
            );
        for event in replay {
            if out.send(event).await.is_err() {
                return;
            }
        }
        self.subscribers.push((id, out));
    }

    async fn fan_out(&mut self, out: SessionOutput) {
        match &out {
            SessionOutput::ForwardStatus(status) => {
                self.statuses.retain(|s| s.id != status.id);
                if status.state != ForwardState::Stopped {
                    self.statuses.push(status.clone());
                }
            }
            SessionOutput::Warning(_) => self.warnings.push(out.clone()),
            _ => {}
        }
        let mut gone = Vec::new();
        for (id, sub) in &self.subscribers {
            if sub.send(out.clone()).await.is_err() {
                gone.push(*id);
            }
        }
        self.subscribers.retain(|(id, _)| !gone.contains(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_pool_has_no_lease() {
        let pool = ConnectionPool::default();
        let (tx, _rx) = mpsc::channel(1);
        let key = key(ProfileId("p".to_owned()), &EffectiveSsh::new("h"));
        assert!(pool.lease(&key, tx).is_none());
        assert_eq!(pool.len(), 0);
        assert!(format!("{pool:?}").contains("connections: 0"));
    }
}
