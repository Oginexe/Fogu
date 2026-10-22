//! `run_local`: a local shell in a `ConPTY`, one task per tab.
//!
//! `portable-pty` exposes blocking readers and writers even on Windows. Two small blocking
//! tasks bridge them to the async session loop: one reads PTY output, one writes queued input.
//! The loop itself keeps the same shape as the Unix implementation (input first, one write and
//! one read per turn, synchronized-update timer, child exit).

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fogu_core::{LocalProfile, Size};
use fogu_term::TermHandle;
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtyPair, PtySize, native_pty_system};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::{Instant, sleep_until, timeout, timeout_at};

use crate::env::build_env;
use crate::pipeline::{Gone, Pump, WRITE_CHUNK};
use crate::{ExitInfo, SessionError, SessionInput, SessionOutput};

/// PTY read buffer.
const READ_CHUNK: usize = 64 * 1024;
/// How long a killed shell may take to exit, and how long closing the `ConPTY` may take.
const CLOSE_GRACE: Duration = Duration::from_secs(2);
/// Upper bound for draining output after the child exited. The output pipe only reaches EOF
/// once the `ConPTY` is closed, so the drain also stops after [`DRAIN_IDLE`] without output.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
/// A pause in the output that ends the drain early.
const DRAIN_IDLE: Duration = Duration::from_millis(100);
/// How often a watched foreground program is checked (kept for API parity; Windows has no
/// portable foreground-process query).
const WATCH_EVERY: Duration = Duration::from_secs(1);

/// Why the main loop stopped.
enum End {
    Exited(io::Result<i32>),
    Close,
}

/// A spawned shell and our ends of its `ConPTY`.
struct Local {
    master: Box<dyn MasterPty + Send>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    /// Output from the blocking reader task.
    read_rx: Receiver<io::Result<Vec<u8>>>,
    /// Queue to the blocking writer task.
    write_tx: Sender<Vec<u8>>,
    /// Written-byte counts / errors from the writer task.
    write_rx: Receiver<io::Result<usize>>,
    /// The child's exit status, from the blocking wait task.
    wait_rx: tokio::task::JoinHandle<io::Result<i32>>,
    /// The PTY read side hit EOF.
    eof: bool,
}

impl Local {
    fn resize(&self, size: Size) {
        let pty_size = pty_size(size);
        if let Err(err) = self.master.resize(pty_size) {
            tracing::warn!(error = %err, "PTY resize failed");
        }
    }
}

/// Session task for a local shell. Errors are reported as `SessionOutput::Error`.
pub(crate) async fn run_local(
    profile: LocalProfile,
    size: Size,
    term: TermHandle,
    mut in_rx: Receiver<SessionInput>,
    out_tx: Sender<SessionOutput>,
) {
    let mut pump = Pump::new(term, out_tx, false);
    let mut local = match spawn(&profile, size) {
        Ok(local) => local,
        Err(err) => {
            tracing::warn!(error = %err, "local shell failed to start");
            let _gone = pump.emit(SessionOutput::Error(err)).await;
            return;
        }
    };
    let status = match run_loop(&mut local, &mut pump, &mut in_rx).await {
        Ok(End::Exited(status)) => {
            if drain(&mut local, &mut pump).await.is_err() {
                release(local).await;
                return;
            }
            status
        }
        Ok(End::Close) => close(&mut local).await,
        Err(Gone) => {
            let _status = close(&mut local).await;
            release(local).await;
            return;
        }
    };
    release(local).await;
    let out = match status {
        Ok(code) => SessionOutput::Exited(ExitInfo {
            code: Some(code),
            signal: None,
        }),
        Err(err) => SessionOutput::Error(SessionError::Io(Arc::new(err))),
    };
    let _gone = pump.emit(out).await;
}

async fn run_loop(
    local: &mut Local,
    pump: &mut Pump,
    in_rx: &mut Receiver<SessionInput>,
) -> Result<End, Gone> {
    let mut watching: Option<Option<String>> = None;
    let mut watch_tick = tokio::time::interval(WATCH_EVERY);
    let mut write_in_flight = false;
    loop {
        let sync_deadline = pump.term.sync_timeout();
        tokio::select! {
            biased;
            input = in_rx.recv() => match input {
                Some(SessionInput::Data(data)) => {
                    if pump.queue_input(&data) {
                        tracing::warn!(len = data.len(), "input backlog full; dropping input");
                        pump.emit(SessionOutput::InputDropped).await?;
                    }
                }
                Some(SessionInput::Resize(size)) => local.resize(size),
                Some(SessionInput::PromptReply(id, _)) => {
                    tracing::debug!(?id, "prompt reply for a local session ignored");
                }
                Some(SessionInput::Forward(_)) => tracing::debug!("forward for a local session ignored"),
                Some(SessionInput::QueryCwd) => {
                    // Windows has no portable `/proc`-style cwd lookup. Local cwd updates
                    // arrive through OSC 7 when the shell integration reports them.
                    pump.emit(SessionOutput::Foreground(None)).await?;
                }
                Some(SessionInput::WatchForeground(on)) => {
                    watching = on.then_some(None);
                }
                Some(SessionInput::Close) | None => return Ok(End::Close),
            },
            written = local.write_rx.recv(), if write_in_flight => {
                write_in_flight = false;
                match written {
                    Some(Ok(n)) => pump.written(n),
                    Some(Err(err)) => {
                        tracing::debug!(error = %err, "PTY write failed; dropping pending input");
                        pump.write_failed();
                    }
                    None => {
                        pump.write_failed();
                    }
                }
            }
            read = local.read_rx.recv(), if !local.eof => match read {
                Some(Ok(bytes)) if bytes.is_empty() => local.eof = true,
                Some(Ok(bytes)) => pump.feed(&bytes).await?,
                Some(Err(err)) => {
                    tracing::warn!(error = %err, "PTY read failed");
                    local.eof = true;
                }
                None => local.eof = true,
            },
            () = sleep_until(sync_deadline.map_or_else(Instant::now, Instant::from_std)),
                if sync_deadline.is_some() => pump.feed(&[]).await?,
            _ = watch_tick.tick(), if watching.is_some() => {
                // No portable foreground-process query on Windows; the watch ends when the
                // shell writes the next prompt (the UI only uses this for a status hint).
                watching = Some(None);
            }
            status = &mut local.wait_rx => {
                return Ok(End::Exited(match status {
                    Ok(Ok(code)) => Ok(code),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(io::Error::other(err.to_string())),
                }));
            }
        }

        // Queue at most one write at a time; input accumulates in `pump.pending` meanwhile.
        if !write_in_flight && !pump.pending.is_empty() {
            let chunk = pump.pending.len().min(WRITE_CHUNK);
            let bytes = pump.pending.get(..chunk).unwrap_or_default().to_vec();
            if local.write_tx.send(bytes).await.is_err() {
                pump.write_failed();
            } else {
                write_in_flight = true;
            }
        }
    }
}

/// Feeds what the child wrote before it exited: until EOF, [`DRAIN_TIMEOUT`], or a pause of
/// [`DRAIN_IDLE`].
async fn drain(local: &mut Local, pump: &mut Pump) -> Result<(), Gone> {
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    while !local.eof {
        let until = deadline.min(Instant::now() + DRAIN_IDLE);
        match timeout_at(until, local.read_rx.recv()).await {
            Ok(Some(Ok(bytes))) if !bytes.is_empty() => pump.feed(&bytes).await?,
            // EOF, a read error, the reader gone, or no output for a while.
            _ => break,
        }
    }
    Ok(())
}

/// Close: kill the child, wait up to [`CLOSE_GRACE`], then reap.
///
/// Only the shell is killed here; what it started still on the console (`ssh`, `python`) ends
/// when [`release`] closes the `ConPTY`, since `ClosePseudoConsole` terminates its attached
/// clients. A program that detached itself (`start`, `DETACHED_PROCESS`) outlives the tab, like
/// `nohup` on Unix.
async fn close(local: &mut Local) -> io::Result<i32> {
    // portable-pty 0.9.0 returns `Err` when `TerminateProcess` succeeds (its check is inverted),
    // so the result means nothing either way: the wait below is what tells.
    let _ = local.killer.kill();
    match timeout(CLOSE_GRACE, &mut local.wait_rx).await {
        Ok(Ok(Ok(code))) => Ok(code),
        Ok(Ok(Err(err))) => Err(err),
        Ok(Err(err)) => Err(io::Error::other(err.to_string())),
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the shell did not exit after being killed",
        )),
    }
}

/// Closes the `ConPTY` without blocking a runtime worker: `ClosePseudoConsole` (the master's
/// drop) runs on a blocking thread, and the output keeps being read and discarded meanwhile,
/// because conhost may wait for its last output to be read before it exits. Bounded by
/// [`CLOSE_GRACE`]; past it the close finishes in the background.
async fn release(local: Local) {
    let Local {
        master,
        killer,
        mut read_rx,
        write_tx,
        write_rx,
        ..
    } = local;
    drop((write_tx, write_rx, killer));
    let closing = tokio::task::spawn_blocking(move || drop(master));
    // The reader task ends at the EOF that follows the close.
    let discard = async { while read_rx.recv().await.is_some() {} };
    let _done = timeout(CLOSE_GRACE, async { tokio::join!(closing, discard) }).await;
}

fn pty_size(size: Size) -> PtySize {
    PtySize {
        rows: size.rows.max(1),
        cols: size.cols.max(2),
        pixel_width: size.px_w,
        pixel_height: size.px_h,
    }
}

fn spawn(profile: &LocalProfile, size: Size) -> Result<Local, SessionError> {
    let program = profile.program.clone().unwrap_or_else(default_shell);
    let spawn_err = |source: io::Error| SessionError::Spawn {
        program: program.clone(),
        source: Arc::new(source),
    };
    let pair = native_pty_system()
        .openpty(pty_size(size))
        .map_err(|err| spawn_err(io::Error::other(err.to_string())))?;
    let mut cmd = CommandBuilder::new(&program);
    cmd.args(&profile.args);
    let cwd = profile
        .cwd
        .clone()
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    cmd.cwd(cwd);
    cmd.env_clear();
    for (key, value) in build_env(std::env::vars_os(), &profile.env) {
        cmd.env(key, value);
    }
    let PtyPair { slave, master } = pair;
    let child = slave
        .spawn_command(cmd)
        .map_err(|err| spawn_err(io::Error::other(err.to_string())))?;
    drop(slave);
    let reader = master
        .try_clone_reader()
        .map_err(|err| spawn_err(io::Error::other(err.to_string())))?;
    let writer = master
        .take_writer()
        .map_err(|err| spawn_err(io::Error::other(err.to_string())))?;
    let killer = child.clone_killer();

    let (read_tx, read_rx) = mpsc::channel(8);
    let (write_tx, mut write_queue) = mpsc::channel::<Vec<u8>>(8);
    let (write_done_tx, write_rx) = mpsc::channel(8);

    tokio::task::spawn_blocking(move || read_loop(reader, read_tx));
    tokio::task::spawn_blocking(move || write_loop(writer, &mut write_queue, write_done_tx));
    let wait_handle = tokio::task::spawn_blocking(move || {
        let mut child = child;
        child.wait().map(|status| status.exit_code().cast_signed())
    });

    Ok(Local {
        master,
        killer,
        read_rx,
        write_tx,
        write_rx,
        wait_rx: wait_handle,
        eof: false,
    })
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the sender is moved into a blocking task"
)]
fn read_loop(mut reader: Box<dyn io::Read + Send>, tx: Sender<io::Result<Vec<u8>>>) {
    let mut buf = vec![0_u8; READ_CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                let _sent = tx.blocking_send(Ok(Vec::new()));
                return;
            }
            Ok(n) => {
                let chunk = buf.get(..n).unwrap_or_default().to_vec();
                if tx.blocking_send(Ok(chunk)).is_err() {
                    return;
                }
            }
            Err(err) => {
                let _sent = tx.blocking_send(Err(err));
                return;
            }
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the sender is moved into a blocking task"
)]
fn write_loop(
    mut writer: Box<dyn io::Write + Send>,
    queue: &mut Receiver<Vec<u8>>,
    done: Sender<io::Result<usize>>,
) {
    while let Some(bytes) = queue.blocking_recv() {
        let result = writer.write_all(&bytes).map(|()| bytes.len());
        let failed = result.is_err();
        if done.blocking_send(result).is_err() || failed {
            return;
        }
    }
}

/// The user's default shell on Windows: PowerShell 7, then Windows PowerShell, then `cmd.exe`.
fn default_shell() -> String {
    for name in ["pwsh.exe", "powershell.exe"] {
        if let Some(path) = find_in_path(name) {
            return path.to_string_lossy().into_owned();
        }
    }
    std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_owned())
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_size_never_uses_zero_columns_or_rows() {
        let size = pty_size(Size::default());
        assert_eq!((size.cols, size.rows), (2, 1));
    }

    #[test]
    fn default_shell_is_never_empty() {
        assert_ne!(default_shell(), "");
    }
}
