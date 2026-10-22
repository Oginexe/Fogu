//! Local shell sessions: a real PTY on Unix (`pty-process`) or `ConPTY` on Windows
//! (`portable-pty`). The public session API is identical on both platforms.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use unix::run_local;
#[cfg(windows)]
pub(crate) use windows::run_local;
