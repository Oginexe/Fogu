//! Finding the Windows OpenSSH agent over its named pipe.
//!
//! Windows ships an agent as a service (`ssh-agent`) that listens on
//! `\\.\pipe\openssh-ssh-agent`. Fogu never starts or stops that service; it only connects to it
//! when the profile asks for agent authentication or forwarding.

use std::path::{Path, PathBuf};
use std::time::Duration;

use russh::keys::agent::client::AgentClient;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

/// How long one connection attempt may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// The named pipe of the Windows OpenSSH agent service.
pub(crate) const DEFAULT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

pub(crate) type Agent = AgentClient<NamedPipeClient>;

/// The configured agent, else `SSH_AUTH_SOCK`, else the Windows OpenSSH agent pipe.
pub(crate) async fn connect(configured: Option<&Path>) -> Option<Agent> {
    find(configured).await.map(|(_, agent)| agent)
}

/// [`connect`], also returning the pipe path (agent forwarding connects to it per channel).
pub(crate) async fn find(configured: Option<&Path>) -> Option<(PathBuf, Agent)> {
    let path = configured
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("SSH_AUTH_SOCK")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PIPE));
    // Git Bash can export a Unix socket path here; only named pipes are usable on Windows.
    if !path
        .to_string_lossy()
        .to_ascii_lowercase()
        .starts_with(r"\\.\pipe\")
    {
        tracing::debug!(path = %path.display(), "SSH_AUTH_SOCK is not a Windows named pipe");
        return None;
    }
    let agent = try_connect(&path).await?;
    Some((path, agent))
}

/// Windows has no private-agent fallback: use the system service or ask for a password.
pub(crate) async fn connect_or_start(configured: Option<&Path>) -> Option<Agent> {
    connect(configured).await
}

/// Serves one `auth-agent@openssh.com` channel from the named-pipe agent.
pub(crate) async fn serve_forward(
    channel: russh::Channel<russh::client::Msg>,
    reply: russh::client::ChannelOpenHandle,
    socket: &Path,
) {
    match timeout_open(socket).await {
        Ok(Ok(mut agent)) => {
            reply.accept().await;
            let mut stream = channel.into_stream();
            let _totals = super::forward::pump(&mut stream, &mut agent).await;
        }
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "forwarded agent request refused: agent unreachable");
        }
        Err(_elapsed) => tracing::warn!("forwarded agent request refused: agent timed out"),
    }
}

async fn timeout_open(path: &Path) -> Result<Result<NamedPipeClient, std::io::Error>, ()> {
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::task::spawn_blocking({
            let path = path.to_path_buf();
            move || ClientOptions::new().open(path)
        }),
    )
    .await
    {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_join)) => Err(()),
        Err(_elapsed) => Err(()),
    }
}

async fn try_connect(path: &Path) -> Option<Agent> {
    match tokio::time::timeout(CONNECT_TIMEOUT, AgentClient::connect_named_pipe(path)).await {
        Ok(Ok(agent)) => {
            tracing::info!(path = %path.display(), "using Windows OpenSSH agent");
            Some(agent)
        }
        Ok(Err(err)) => {
            tracing::debug!(path = %path.display(), error = %err, "no SSH agent here");
            None
        }
        Err(_elapsed) => None,
    }
}
