//! Finding the Windows OpenSSH agent over its named pipe.
//!
//! Windows ships an agent as a service (`ssh-agent`) that listens on
//! `\\.\pipe\openssh-ssh-agent`. Fogu never starts or stops that service; it only connects to it
//! when the profile asks for agent authentication or forwarding. A pipe owned by anyone but
//! SYSTEM, Administrators or the user is refused: another user can create that pipe while the
//! service is stopped, and would then see every signing request.

use std::io;
use std::os::windows::io::AsHandle as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use russh::keys::agent::client::AgentClient;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

/// How long one connection attempt may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// `ERROR_PIPE_BUSY`: every instance of the pipe is in use; retry shortly.
const ERROR_PIPE_BUSY: i32 = 231;

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
    match tokio::time::timeout(CONNECT_TIMEOUT, open_trusted(socket)).await {
        Ok(Ok(mut pipe)) => {
            reply.accept().await;
            let mut stream = channel.into_stream();
            let _totals = super::forward::pump(&mut stream, &mut pipe).await;
        }
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "forwarded agent request refused: agent unreachable");
        }
        Err(_elapsed) => tracing::warn!("forwarded agent request refused: agent timed out"),
    }
}

/// Opens the agent's pipe, retrying while every instance is busy, and keeps it only if its owner
/// is trusted ([`fogu_core::winsec::pipe_owner_trusted`]).
async fn open_trusted(path: &Path) -> io::Result<NamedPipeClient> {
    let pipe = loop {
        match ClientOptions::new().open(path) {
            Ok(pipe) => break pipe,
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY) => {}
            Err(err) => return Err(err),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    if !fogu_core::winsec::pipe_owner_trusted(pipe.as_handle())? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the agent pipe belongs to another user; refused",
        ));
    }
    Ok(pipe)
}

async fn try_connect(path: &Path) -> Option<Agent> {
    match tokio::time::timeout(CONNECT_TIMEOUT, open_trusted(path)).await {
        Ok(Ok(pipe)) => {
            tracing::info!(path = %path.display(), "using Windows OpenSSH agent");
            Some(AgentClient::connect(pipe))
        }
        Ok(Err(err)) if err.kind() == io::ErrorKind::PermissionDenied => {
            tracing::warn!(path = %path.display(), error = %err, "SSH agent pipe not trusted");
            None
        }
        Ok(Err(err)) => {
            tracing::debug!(path = %path.display(), error = %err, "no SSH agent here");
            None
        }
        Err(_elapsed) => None,
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests")]

    use tokio::net::windows::named_pipe::ServerOptions;

    use super::*;

    #[tokio::test]
    async fn a_pipe_created_by_this_user_is_trusted() {
        let name = format!(r"\\.\pipe\fogu-agent-test-{}", std::process::id());
        let _server = ServerOptions::new().create(&name).unwrap();
        open_trusted(Path::new(&name)).await.unwrap();
    }
}
