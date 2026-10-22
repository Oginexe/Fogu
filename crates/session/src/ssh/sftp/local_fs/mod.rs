//! Local filesystem access for downloads.
//!
//! The two platforms share the same small vocabulary ([`LocalDir`], [`DirHandle`], [`Mode`],
//! [`Existing`]); their security models differ. Unix uses directory file descriptors and
//! `O_NOFOLLOW`, so a planted symlink can never redirect a write. Windows has no `openat`; it
//! validates each name component, refuses symlinks and junctions on the path, and uses
//! `create_new` for new files.

#[cfg(windows)]
use std::io;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use unix::{
    DirHandle, LocalDir, available_space, create_file, existing, file_info, finish,
    open_for_resume, remove,
};
#[cfg(windows)]
pub(crate) use windows::{
    DirHandle, LocalDir, available_space, create_file, existing, file_info, finish,
    open_for_resume, remove,
};

pub(crate) use crate::sftp::NAME_MAX;
use crate::sftp::NameError;

/// Accepts `name` as one local path component on this platform.
pub(crate) fn validate_name(name: &str) -> Result<&str, NameError> {
    let name = crate::sftp::validate_name(name)?;
    #[cfg(windows)]
    windows_name(name)?;
    Ok(name)
}

/// Windows adds rules the SFTP/Unix name check does not cover: reserved device names, characters
/// that name a stream or a separator, and trailing dots/spaces that Windows silently strips.
#[cfg(windows)]
fn windows_name(name: &str) -> Result<(), NameError> {
    const RESERVED: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    if name.ends_with(['.', ' ']) {
        return Err(NameError::Invalid);
    }
    if name
        .chars()
        .any(|c| matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err(NameError::Invalid);
    }
    let stem = name
        .split_once('.')
        .map_or(name, |(stem, _rest)| stem)
        .trim_end_matches(['.', ' ']);
    if RESERVED
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return Err(NameError::Invalid);
    }
    Ok(())
}

/// Suffix of a download in progress.
pub(crate) const PART_SUFFIX: &str = ".part";

/// `<name>.part`, if that still fits in [`NAME_MAX`].
pub(crate) fn part_name(name: &str) -> Option<String> {
    (name.len() + PART_SUFFIX.len() <= NAME_MAX).then(|| format!("{name}{PART_SUFFIX}"))
}

/// Local permission bits for a downloaded file.
#[cfg(unix)]
pub(crate) use rustix::fs::Mode;

/// Local permission bits for a downloaded file. Windows does not enforce them; the value is only
/// carried so both platforms share one signature.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mode(u32);

#[cfg(windows)]
impl Mode {
    /// Wraps raw permission bits.
    pub(crate) const fn from_raw_mode(mode: u32) -> Self {
        Self(mode)
    }
}

/// Local mode for a downloaded file: `0644`, or `0755` when `keep_exec` (the
/// `keep_executable_bit` option) and the remote mode has any `x` bit. setuid/setgid/sticky are
/// never copied.
pub(crate) fn file_mode(remote_mode: Option<u32>, keep_exec: bool) -> Mode {
    if keep_exec && remote_mode.is_some_and(|m| m & 0o111 != 0) {
        Mode::from_raw_mode(0o755)
    } else {
        Mode::from_raw_mode(0o644)
    }
}

/// What exists under a name (not following symlinks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Existing {
    Nothing,
    File,
    Dir,
    /// Symlink, junction, device, FIFO, socket.
    Other,
}

/// Converts an I/O result to [`Existing`] for `symlink_metadata` style probes.
#[cfg(windows)]
pub(crate) fn classify(metadata: io::Result<std::fs::Metadata>) -> io::Result<Existing> {
    match metadata {
        Ok(meta) => {
            let kind = meta.file_type();
            if is_reparse(&meta) {
                return Ok(Existing::Other);
            }
            Ok(if kind.is_file() {
                Existing::File
            } else if kind.is_dir() {
                Existing::Dir
            } else {
                Existing::Other
            })
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Existing::Nothing),
        Err(err) => Err(err),
    }
}

/// Whether a path entry redirects somewhere else: a symlink or a junction (std reports every
/// name-surrogate reparse point as a symlink). Other reparse points are left alone: `OneDrive`
/// placeholders ("Files On-Demand") and `WOF`-compressed files (`compact /c`) are ordinary
/// files and folders, and `Downloads` is on `OneDrive` by default on Windows 11.
#[cfg(windows)]
pub(crate) fn is_reparse(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}
