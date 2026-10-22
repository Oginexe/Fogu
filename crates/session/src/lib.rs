//! `fogu-session`: the one session API: `open()` spawns a transport task per tab that
//! feeds a [`TermHandle`] and talks to the UI over two bounded channels. Transports: a local
//! shell (`run_local`) and, behind the default `ssh` feature, an SSH shell channel (`run_ssh`).

mod env;
mod local;
mod pipeline;
mod prompt;
#[cfg(all(feature = "ssh", unix))]
mod secrets;
#[cfg(all(feature = "ssh", windows))]
#[path = "secrets_windows.rs"]
mod secrets;
pub mod sftp;
#[cfg(feature = "ssh")]
mod ssh;
mod supervise;

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
#[cfg(feature = "ssh")]
use fogu_core::ProfileId;
use fogu_core::{EffectiveProfile, EffectiveSsh, PortForward, Size};
use fogu_term::{ClipboardType, PromptMark, TermHandle};
use tokio::runtime::{Handle, Runtime};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::Instrument as _;

pub use env::build_env;
pub use prompt::{
    KbdPrompt, PROMPT_INSTRUCTIONS_MAX_CHARS, PROMPT_MAX_COUNT, PROMPT_TEXT_MAX_CHARS, PromptId,
    PromptKind, PromptReply, Remember, sanitize_remote,
};
#[cfg(feature = "ssh")]
pub use secrets::{SecretError, SecretStore, Secrets};
pub use sftp::{SftpCmd, SftpEvent, SftpHandle, SftpRequest, display_name, validate_name};
#[cfg(feature = "ssh")]
pub use ssh::algorithms::{
    Supported as SupportedAlgorithms, non_default as non_default_algorithms,
    supported as supported_algorithms,
};
#[cfg(feature = "ssh")]
pub use ssh::key_fingerprint;
#[cfg(feature = "ssh")]
pub use ssh::pool::ConnectionPool;
#[cfg(feature = "ssh")]
pub use ssh::{PROMPT_TIMEOUT, SshPaths};
pub use supervise::supervise;

/// Capacity of the UI → session input channel.
const INPUT_CAPACITY: usize = 64;
/// Capacity of the session → UI event channel.
const OUTPUT_CAPACITY: usize = 256;

/// Owns the tokio runtime that runs every session task (2 worker threads) and the SSH
/// connections tabs share (`reuse_session`).
#[derive(Debug)]
pub struct SessionRuntime {
    rt: Runtime,
    #[cfg(feature = "ssh")]
    pool: ConnectionPool,
    #[cfg(feature = "ssh")]
    secrets: Secrets,
}

impl SessionRuntime {
    /// Builds the multi-thread runtime; stored secrets use the desktop Secret Service.
    pub fn new() -> io::Result<Self> {
        let rt = Self::runtime()?;
        Ok(Self {
            #[cfg(feature = "ssh")]
            secrets: Secrets::new(rt.handle().clone()),
            #[cfg(feature = "ssh")]
            pool: ConnectionPool::default(),
            rt,
        })
    }

    /// [`Self::new`] with a fixed secret store (tests; `SecretStore::Disabled` = none).
    #[cfg(feature = "ssh")]
    pub fn with_store(store: SecretStore) -> io::Result<Self> {
        let rt = Self::runtime()?;
        Ok(Self {
            secrets: Secrets::with_store(rt.handle().clone(), store),
            pool: ConnectionPool::default(),
            rt,
        })
    }

    fn runtime() -> io::Result<Runtime> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("fogu-session")
            .enable_all()
            .build()
    }

    /// The stored secrets (passwords, passphrases) of this runtime's sessions.
    #[cfg(feature = "ssh")]
    pub fn secrets(&self) -> &Secrets {
        &self.secrets
    }

    /// Handle to pass to [`open`].
    pub fn handle(&self) -> &Handle {
        self.rt.handle()
    }

    /// [`open_ssh`], reusing a live connection of the same profile (same id and same resolved
    /// options) when `ssh.reuse_session`: no second login, the tab gets a new channel.
    #[cfg(feature = "ssh")]
    pub fn open_ssh_shared(
        &self,
        profile: &ProfileId,
        ssh: &EffectiveSsh,
        paths: SshPaths,
        size: Size,
        term: TermHandle,
    ) -> SessionHandle {
        let pooled = ssh::pool::Pooled {
            pool: self.pool.clone(),
            profile: profile.clone(),
        };
        let secrets = self.secrets.clone();
        open_ssh_in(self.handle(), ssh, paths, secrets, Some(pooled), size, term)
    }
}

/// The UI's side of one session.
#[derive(Debug)]
pub struct SessionHandle {
    /// Keys, paste chunks, resizes, prompt replies, close.
    pub input: Sender<SessionInput>,
    /// Everything the session reports back; merged into one iced subscription.
    pub events: Receiver<SessionOutput>,
    /// SSH sessions only: the SFTP engine on the same connection (idle until the first
    /// command; commands sent before the shell is up wait).
    pub sftp: Option<SftpHandle>,
}

/// UI → session messages.
#[derive(Debug)]
pub enum SessionInput {
    /// Already-encoded keys or paste chunks.
    Data(Bytes),
    /// New size; the UI resizes the `TermHandle` itself first.
    Resize(Size),
    /// Answer to a [`SessionOutput::Prompt`].
    PromptReply(PromptId, PromptReply),
    /// Ask for the foreground process's current directory (on demand only, for opening a new tab in the same directory);
    /// the session replies with [`SessionOutput::Cwd`] if it could determine one.
    QueryCwd,
    /// SSH: add or remove a port forward at runtime (ignored by local sessions and before the
    /// shell is up).
    Forward(ForwardCmd),
    /// Local: report [`SessionOutput::ForegroundDone`] once the program running in the shell
    /// (now, or the next one started) ends; `false` cancels. Ignored by SSH sessions.
    WatchForeground(bool),
    /// Close the transport; the session answers with `Exited`.
    Close,
}

/// Session → UI messages.
#[derive(Clone, Debug)]
pub enum SessionOutput {
    /// The terminal changed; sent only when `dirty` goes false → true.
    Wakeup,
    /// Sanitized window title (empty = reset to default).
    Title(String),
    /// Terminal bell.
    Bell,
    /// Local, with a [`SessionInput::QueryCwd`] reply: the program running in the shell
    /// (`/proc/<pid>/comm`, sanitized), `None` when the shell itself is in front.
    Foreground(Option<String>),
    /// Local: the watched program ended ([`SessionInput::WatchForeground`]); its name.
    ForegroundDone(String),
    /// Current working directory (OSC 7/1337, or an on-demand [`SessionInput::QueryCwd`] reply).
    Cwd {
        /// The reported directory.
        path: PathBuf,
        /// `true` when the reporting host wasn't the local machine (OSC 7 with a foreign host);
        /// such a path cannot be validated or opened locally.
        remote: bool,
    },
    /// Progress (OSC 9;4).
    Progress(Option<u8>),
    /// Desktop notification (OSC 9 / 777); no title for OSC 9.
    Notify {
        /// Present only for OSC 777.
        title: Option<String>,
        /// Sanitized, capped body text.
        body: String,
    },
    /// Shell-integration prompt mark (OSC 133); not used by the UI yet.
    PromptMark(PromptMark),
    /// User input was dropped: the program stopped reading and the backlog is full. Sent once
    /// per backlog.
    InputDropped,
    /// The session needs an answer from the user (SSH): reply with
    /// [`SessionInput::PromptReply`] carrying the same id within [`PROMPT_TIMEOUT`]. The
    /// third field names the jump host (`user@host:port`) the prompt is for; `None` = the
    /// profile's own host.
    Prompt(PromptId, PromptKind, Option<String>),
    /// Something the user should know about this session (warning badge / toast).
    Warning(SessionWarning),
    /// OSC 52 clipboard write; the UI applies the policy.
    ClipboardStore(ClipboardRequest),
    /// A port forward started, failed, changed its connection count or stopped.
    ForwardStatus(ForwardStatus),
    /// SSH: the connection this tab runs on (tabs sharing a connection report the same id).
    Connection(ConnectionId),
    /// The transport ended.
    Exited(ExitInfo),
    /// The session failed.
    Error(SessionError),
}

/// Non-fatal conditions a session reports (closed set).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionWarning {
    /// `verify_host_keys = false`: the server's identity was not checked (persistent badge).
    HostKeyNotVerified,
    /// Profile options that are set but not implemented yet (accepted, ignored).
    Unsupported(Vec<String>),
    /// A port forward listens on an address other machines can reach (sanitized label,
    /// e.g. `L 0.0.0.0:8080 → web:80`).
    ForwardExposed(String),
    /// The local SSH agent is forwarded: the server can use its keys (persistent badge).
    AgentForwarded,
    /// X11 is forwarded: remote programs can read this display's input (persistent badge).
    X11Forwarded,
    /// Algorithm names the SSH library doesn't know; ignored (sanitized).
    UnknownAlgorithms(Vec<String>),
    /// Algorithms outside the library's defaults (weaker or legacy) are enabled.
    WeakAlgorithms(Vec<String>),
    /// Stored passwords / passphrases can't be used or saved right now (sanitized reason); the
    /// user is asked instead.
    SecretStore(String),
    /// The profile's `cwd` or login scripts could not be used (sanitized reason).
    ShellSetup(String),
}

/// Identifies one SSH connection of this process (never reused).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

/// Identifies one port forward of a session (assigned by the session, never reused).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ForwardId(pub u64);

/// Runtime control of a session's port forwards.
#[derive(Clone, Debug)]
pub enum ForwardCmd {
    /// Start this forward; the session answers with [`SessionOutput::ForwardStatus`].
    Add(PortForward),
    /// Stop this forward (remote forwards are cancelled on the server).
    Remove(ForwardId),
}

/// State of one port forward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardState {
    /// Accepting connections.
    Listening,
    /// Could not start (port in use, refused by the server…): sanitized reason. The forward
    /// stays listed until it is removed.
    Error(String),
    /// Removed, or the session ended; the last status of this id.
    Stopped,
}

/// One forward's status report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardStatus {
    /// Which forward.
    pub id: ForwardId,
    /// What it forwards (as requested).
    pub forward: PortForward,
    /// Listening / error / stopped.
    pub state: ForwardState,
    /// Connections currently being forwarded.
    pub active_connections: usize,
}
/// Why a server's host key was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HostKeyFailure {
    /// The user declined an unknown key (or the prompt was abandoned).
    #[error("host key not accepted")]
    Rejected,
    /// The key differs from the recorded one and was not explicitly replaced.
    #[error("host key changed (possible man-in-the-middle attack); connection refused")]
    Changed,
    /// The key is marked `@revoked` in a `known_hosts` file.
    #[error("host key is revoked")]
    Revoked,
    /// The server presented a certificate; certificates are not supported yet.
    #[error("host certificates are not supported")]
    Certificate,
}

/// OSC 52 write request forwarded to the UI. `Debug` shows only the target and the length: the
/// payload is attacker-chosen text that must never reach a log.
#[derive(Clone)]
pub struct ClipboardRequest {
    /// Clipboard or primary selection.
    pub target: ClipboardType,
    /// Text the remote wants to store.
    pub payload: String,
    /// Payload length in bytes.
    pub len: usize,
}

impl fmt::Debug for ClipboardRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClipboardRequest")
            .field("target", &self.target)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// How the transport ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitInfo {
    /// Exit code, if the process exited normally.
    pub code: Option<i32>,
    /// Terminating signal, if it was killed by one.
    pub signal: Option<i32>,
}

/// Session failures reported to the UI. Never carries secrets.
#[derive(Clone, Debug, thiserror::Error)]
pub enum SessionError {
    /// The local program could not be started.
    #[error("failed to start {program}")]
    Spawn {
        /// Program path or name.
        program: String,
        /// Underlying OS error.
        #[source]
        source: Arc<io::Error>,
    },
    /// I/O failure on a running session.
    #[error("session I/O error")]
    Io(#[source] Arc<io::Error>),
    /// The session task panicked; the pane's `TermHandle` must not be reused.
    #[error("session task crashed")]
    Crashed,
    /// The SSH profile has no host.
    #[error("no host configured")]
    NoHost,
    /// TCP connection failed.
    #[error("could not connect to {target}")]
    Connect {
        /// `host:port` as configured (sanitized).
        target: String,
        /// Underlying OS error.
        #[source]
        source: Arc<io::Error>,
    },
    /// Connect, handshake or an authentication request exceeded `ready_timeout`.
    #[error("connection timed out")]
    Timeout,
    /// No answer to a prompt within [`PROMPT_TIMEOUT`].
    #[error("no answer to the prompt in time")]
    PromptTimeout,
    /// The server's host key was not accepted.
    #[error(transparent)]
    HostKey(HostKeyFailure),
    /// The profile's route (jump host, proxy) can't be followed exactly (see
    /// `EffectiveSsh::route_problems`); a direct connection could reach a different machine,
    /// so none is made.
    #[error("not connecting: {0} (a direct connection could reach a different machine)")]
    Route(String),
    /// The SOCKS5 / HTTP proxy or the proxy command failed (sanitized text).
    #[error("proxy: {0}")]
    Proxy(String),
    /// Connecting or logging in to a jump host failed.
    #[error("jump host {hop}: {error}")]
    Jump {
        /// `user@host:port` of the hop (sanitized).
        hop: String,
        /// What went wrong there.
        error: Box<SessionError>,
    },
    /// Every allowed authentication method failed.
    #[error("authentication failed")]
    AuthFailed,
    /// Any other SSH failure; the text is sanitized and capped (it may quote the server).
    #[error("SSH error: {0}")]
    Ssh(String),
}

/// Starts a session task on `rt` for `profile` that feeds `term` and returns the UI's side of it.
/// SSH profiles use the default [`SshPaths`] (our `known_hosts` under the default config dir);
/// see [`open_ssh`] to choose them.
pub fn open(
    rt: &Handle,
    profile: &EffectiveProfile,
    size: Size,
    term: TermHandle,
) -> SessionHandle {
    match profile {
        EffectiveProfile::Local(local) => spawn(rt, |in_rx, out_tx| {
            let span = tracing::info_span!("session", kind = "local");
            rt.spawn(local::run_local(local.clone(), size, term, in_rx, out_tx).instrument(span))
        }),
        #[cfg(feature = "ssh")]
        EffectiveProfile::Ssh(ssh) => {
            let secrets = Secrets::new(rt.clone());
            open_ssh(rt, ssh, SshPaths::default_for_user(), secrets, size, term)
        }
        #[cfg(not(feature = "ssh"))]
        EffectiveProfile::Ssh(ssh) => unsupported_ssh(rt, ssh),
    }
}

/// [`open`] for an SSH profile with explicit `known_hosts` locations (`--config-dir`, tests).
/// The connection is never shared; see [`SessionRuntime::open_ssh_shared`]. `secrets` holds the
/// stored passwords / passphrases (usually [`SessionRuntime::secrets`]).
#[cfg(feature = "ssh")]
pub fn open_ssh(
    rt: &Handle,
    ssh: &EffectiveSsh,
    paths: SshPaths,
    secrets: Secrets,
    size: Size,
    term: TermHandle,
) -> SessionHandle {
    open_ssh_in(rt, ssh, paths, secrets, None, size, term)
}

#[cfg(feature = "ssh")]
fn open_ssh_in(
    rt: &Handle,
    ssh: &EffectiveSsh,
    paths: SshPaths,
    secrets: Secrets,
    pooled: Option<ssh::pool::Pooled>,
    size: Size,
    term: TermHandle,
) -> SessionHandle {
    let (sftp, sftp_ends) = ssh::sftp::channels();
    let mut handle = spawn(rt, |in_rx, out_tx| {
        let span = tracing::info_span!("session", kind = "ssh");
        let task = ssh::run_ssh(
            ssh.clone(),
            paths,
            secrets,
            pooled,
            size,
            term,
            in_rx,
            out_tx,
            sftp_ends,
        );
        rt.spawn(task.instrument(span))
    });
    handle.sftp = Some(sftp);
    handle
}

/// Without the `ssh` feature an SSH profile fails at once with [`SessionError::Spawn`]
/// (`ErrorKind::Unsupported`), so the pane shows the crashed state.
#[cfg(not(feature = "ssh"))]
fn unsupported_ssh(rt: &Handle, ssh: &EffectiveSsh) -> SessionHandle {
    let program = format!("ssh {}", ssh.host);
    spawn(rt, |in_rx, out| {
        rt.spawn(async move {
            let source = Arc::new(io::Error::from(io::ErrorKind::Unsupported));
            drop(in_rx);
            let _gone = out
                .send(SessionOutput::Error(SessionError::Spawn {
                    program,
                    source,
                }))
                .await;
        })
    })
}

/// Creates the channels, starts the task built by `start` and its supervisor.
fn spawn(
    rt: &Handle,
    start: impl FnOnce(Receiver<SessionInput>, Sender<SessionOutput>) -> tokio::task::JoinHandle<()>,
) -> SessionHandle {
    let (in_tx, in_rx) = mpsc::channel(INPUT_CAPACITY);
    let (out_tx, out_rx) = mpsc::channel(OUTPUT_CAPACITY);
    let task = start(in_rx, out_tx.clone());
    rt.spawn(supervise(task, out_tx));
    SessionHandle {
        input: in_tx,
        events: out_rx,
        sftp: None,
    }
}
