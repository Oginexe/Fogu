//! `run_ssh`: an interactive SSH shell, one task per tab. Every russh call lives in this module
//! (russh is 0.x and breaks per minor): `connect.rs` (handler, host-key prompts, transport config),
//! `hostkeys.rs` (`known_hosts`), `auth.rs` (authentication methods), `shell.rs` (PTY channel
//! through the shared [`Pump`] pipeline), `pool.rs` (the connection's driver, shared by tabs with
//! `reuse_session`), `x11.rs` / `agent.rs` (forwarding).
//!
//! Attacker input here: everything the server sends (banner, keyboard-interactive texts, error
//! strings, channel data) and, for imported profiles, the host name. Service lines and prompt
//! texts are sanitized ([`sanitize_remote`]); channel data goes through the terminal like any
//! program output. Secrets exist only as `SecretString` and are exposed only at the russh call.

#[cfg(unix)]
mod agent;
#[cfg(windows)]
#[path = "agent_windows.rs"]
mod agent;
pub mod algorithms;
mod auth;
pub use auth::key_fingerprint;
mod connect;
mod forward;
mod hostkeys;
pub(crate) mod pool;
mod proxy;
pub(crate) mod sftp;
mod shell;
mod transport;
#[cfg(unix)]
mod x11;
#[cfg(windows)]
#[path = "x11_windows.rs"]
mod x11;

use std::path::{Path, PathBuf};
use std::time::Duration;

use fogu_core::{EffectiveSsh, Size};
use fogu_term::TermHandle;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::timeout;

use self::pool::Pooled;
use self::sftp::SftpEnds;
use crate::pipeline::{Gone, Pump};
use crate::prompt::{PROMPT_TEXT_MAX_CHARS, sanitize_remote};
use crate::secrets::Secrets;
use crate::{
    ExitInfo, PromptId, PromptKind, PromptReply, SessionError, SessionInput, SessionOutput,
    SessionWarning,
};

/// How long a prompt waits for its [`SessionInput::PromptReply`] before the connection aborts,
/// unless the profile sets `prompt_timeout`.
pub const PROMPT_TIMEOUT: Duration =
    Duration::from_millis(fogu_core::config::ssh_opts::DEFAULT_PROMPT_TIMEOUT_MS);
/// `ready_timeout` when the profile sets none (20 s).
const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Where host keys are looked up and saved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshPaths {
    /// Our `known_hosts` (read + append, `0600`), consulted first.
    pub known_hosts: PathBuf,
    /// The user's OpenSSH `known_hosts`, read-only (`None` = don't consult one).
    pub system_known_hosts: Option<PathBuf>,
}

impl SshPaths {
    /// `<config_dir>/known_hosts` + `~/.ssh/known_hosts`.
    #[must_use]
    pub fn in_config_dir(config_dir: &Path) -> Self {
        Self {
            known_hosts: config_dir.join("known_hosts"),
            system_known_hosts: fogu_core::platform::home_dir()
                .map(|home| home.join(".ssh").join("known_hosts")),
        }
    }

    /// [`Self::in_config_dir`] of the platform config directory.
    #[must_use]
    pub fn default_for_user() -> Self {
        Self::in_config_dir(&fogu_core::platform::config_dir())
    }

    fn files(&self) -> Vec<PathBuf> {
        std::iter::once(self.known_hosts.clone())
            .chain(self.system_known_hosts.clone())
            .collect()
    }
}

/// Why the session stops before the shell ends normally.
pub(crate) enum Stop {
    /// The UI dropped its receiver: stop quietly.
    Gone,
    /// The user closed the tab.
    Closed,
    /// Report this error.
    Failed(SessionError),
}

impl From<Gone> for Stop {
    fn from(Gone: Gone) -> Self {
        Self::Gone
    }
}

impl From<SessionError> for Stop {
    fn from(err: SessionError) -> Self {
        Self::Failed(err)
    }
}

/// The session's side of the UI while connecting: service lines into the terminal, prompts out,
/// replies (and resizes/close) in.
pub(crate) struct Ui {
    pub(crate) pump: Pump,
    pub(crate) in_rx: Receiver<SessionInput>,
    /// Latest size the UI asked for.
    pub(crate) size: Size,
    next_prompt: u64,
    /// The profile's `prompt_timeout`; `None` = no limit.
    prompt_timeout: Option<Duration>,
    /// The SFTP engine's channel ends, handed to the engine once the shell is up.
    pub(crate) sftp: Option<SftpEnds>,
    /// `user@host:port` of the jump host being connected, sent with each prompt.
    pub(crate) via: Option<String>,
    /// Stored passwords / passphrases.
    pub(crate) secrets: Secrets,
}

impl Ui {
    /// Writes one service line (sanitized) into the terminal.
    pub(crate) async fn service(&mut self, text: &str) -> Result<(), Gone> {
        let text = sanitize_remote(text, 4 * PROMPT_TEXT_MAX_CHARS, false);
        let line = format!("\x1b[1;36m*\x1b[0m {text}\r\n");
        self.pump.feed(line.as_bytes()).await
    }

    /// Writes the server's auth banner (sanitized, newlines kept) unless `skip_banner`.
    pub(crate) async fn banner(&mut self, text: &str) -> Result<(), Gone> {
        let text = sanitize_remote(text, 8 * 1024, true).replace('\n', "\r\n");
        self.pump.feed(text.as_bytes()).await?;
        if !text.ends_with('\n') {
            self.pump.feed(b"\r\n").await?;
        }
        Ok(())
    }

    /// Sends `kind` to the UI and waits (≤ the profile's `prompt_timeout`) for its reply.
    pub(crate) async fn ask(&mut self, kind: PromptKind) -> Result<PromptReply, Stop> {
        let id = PromptId(self.next_prompt);
        self.next_prompt += 1;
        tracing::debug!(?id, ?kind, "prompt");
        self.pump
            .emit(SessionOutput::Prompt(id, kind, self.via.clone()))
            .await?;
        let limit = self.prompt_timeout;
        let wait = async {
            loop {
                match self.in_rx.recv().await {
                    Some(SessionInput::PromptReply(reply_id, reply)) if reply_id == id => {
                        return Ok(reply);
                    }
                    other => self.idle_input(other.as_ref())?,
                }
            }
        };
        match limit {
            Some(limit) => timeout(limit, wait)
                .await
                .unwrap_or(Err(Stop::Failed(SessionError::PromptTimeout))),
            None => wait.await,
        }
    }

    /// Input that arrives while no shell is running: sizes are remembered, close stops, keys and
    /// stale prompt replies are dropped.
    pub(crate) fn idle_input(&mut self, input: Option<&SessionInput>) -> Result<(), Stop> {
        match input {
            Some(SessionInput::Resize(size)) => self.size = *size,
            Some(SessionInput::Data(_)) => {
                tracing::debug!("input before the shell started dropped");
            }
            Some(SessionInput::PromptReply(id, _)) => tracing::debug!(?id, "stale prompt reply"),
            Some(SessionInput::QueryCwd | SessionInput::WatchForeground(_)) => {}
            Some(SessionInput::Forward(_)) => {
                tracing::debug!("forward command before the shell started dropped");
            }
            Some(SessionInput::Close) | None => return Err(Stop::Closed),
        }
        Ok(())
    }
}

/// Session task for an SSH shell; with `pooled` (and the profile's `reuse_session`) it reuses
/// a live connection of the same profile. Errors are shown as a service line and reported as
/// `SessionOutput::Error`.
#[expect(
    clippy::too_many_arguments,
    reason = "the task's inputs, passed once by `open_ssh_in`"
)]
pub(crate) async fn run_ssh(
    ssh: EffectiveSsh,
    paths: SshPaths,
    secrets: Secrets,
    pooled: Option<Pooled>,
    size: Size,
    term: TermHandle,
    in_rx: Receiver<SessionInput>,
    out_tx: Sender<SessionOutput>,
    sftp: SftpEnds,
) {
    let mut ui = Ui {
        pump: Pump::new(term, out_tx, true),
        in_rx,
        size,
        next_prompt: 0,
        prompt_timeout: ssh.prompt_timeout,
        sftp: Some(sftp),
        via: None,
        secrets,
    };
    let pooled = pooled.filter(|_| ssh.reuse_session);
    let out = match session(&ssh, &paths, pooled, &mut ui).await {
        Ok(info) => SessionOutput::Exited(info),
        Err(Stop::Gone) => return,
        Err(Stop::Closed) => SessionOutput::Exited(ExitInfo {
            code: None,
            signal: None,
        }),
        Err(Stop::Failed(err)) => {
            tracing::warn!(error = %err, "SSH session failed");
            if ui.service(&format!("Error: {err}")).await.is_err() {
                return;
            }
            SessionOutput::Error(err)
        }
    };
    let _gone = ui.pump.emit(out).await;
}

async fn session(
    ssh: &EffectiveSsh,
    paths: &SshPaths,
    pooled: Option<Pooled>,
    ui: &mut Ui,
) -> Result<ExitInfo, Stop> {
    let unsupported = ssh.unsupported();
    if !unsupported.is_empty() {
        let list = unsupported.join(", ");
        tracing::warn!(options = %list, "SSH profile options not supported yet");
        ui.service(&format!("Not supported yet (ignored): {list}"))
            .await?;
        ui.pump
            .emit(SessionOutput::Warning(SessionWarning::Unsupported(
                unsupported,
            )))
            .await?;
    }
    let ready = ssh.ready_timeout.unwrap_or(DEFAULT_READY_TIMEOUT);
    if let Some(Pooled { pool, profile }) = &pooled {
        let key = pool::key(profile.clone(), ssh);
        if let Some(lease) = pool.lease(&key, ui.pump.sender()) {
            ui.service(&format!(
                "Reusing the connection to {}@{}:{}",
                ssh.user, ssh.host, ssh.port
            ))
            .await?;
            return shell::run(lease, None, ssh, ui, ready).await;
        }
    }
    let mut conn = connect::connect(ssh, paths, ui, ready, 0).await?;
    auth::authenticate(&mut conn, ssh, ui, ready).await?;
    conn.drain_events(ssh, ui).await?;
    let shared = pooled.is_some();
    let (lease, driver) = pool::start(conn, ssh, pooled, ui.pump.sender());
    // An unshared connection closes with this tab; a pooled one when its last tab is gone.
    let driver = (!shared).then_some(driver);
    shell::run(lease, driver, ssh, ui, ready).await
}
