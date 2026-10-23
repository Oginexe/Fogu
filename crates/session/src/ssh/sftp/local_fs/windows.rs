//! Windows local writes.
//!
//! There is no `openat`/`O_NOFOLLOW`, so the model is: canonical root, every component validated
//! by [`validate_name`], every existing component checked with `symlink_metadata` and refused if
//! it is a symlink or junction, new files created with `create_new`, files opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT` (a link planted after the check is opened itself and refused),
//! and the final publish done with `rename` only after re-checking the target. This closes the
//! common escape paths; a same-user process racing the checks is outside what a non-privileged,
//! `unsafe`-free Windows program can fully prevent without `NtCreateFile`.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use super::{Existing, Mode, classify, is_reparse, validate_name};

/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a symlink or junction itself, never what it points at.
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// A directory below the destination root.
#[derive(Clone, Debug)]
pub(crate) struct DirHandle {
    path: PathBuf,
}

/// The download destination, opened once.
#[derive(Debug)]
pub(crate) struct LocalDir {
    root: DirHandle,
}

impl LocalDir {
    /// Opens the user-chosen destination directory.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let path = path.canonicalize()?;
        let meta = std::fs::metadata(&path)?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "the download destination is not a directory",
            ));
        }
        Ok(Self {
            root: DirHandle { path },
        })
    }

    /// The destination directory itself.
    pub(crate) fn fd(&self) -> &DirHandle {
        &self.root
    }

    /// Opens `rel` (validated names) below the root, refusing reparse points on the way.
    pub(crate) fn open_dir(&self, rel: &[String]) -> io::Result<DirHandle> {
        let mut path = self.root.path.clone();
        for name in rel {
            let child = safe_child(&path, name)?;
            let meta = std::fs::symlink_metadata(&child)?;
            if is_reparse(&meta) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a path component is a symlink or junction; refusing to follow it",
                ));
            }
            if !meta.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "a path component is not a directory",
                ));
            }
            path = child;
        }
        Ok(DirHandle { path })
    }

    /// Creates `rel`; an existing directory is fine, an existing symlink/junction is an error.
    pub(crate) fn make_dir(&self, rel: &[String]) -> io::Result<bool> {
        let Some((name, parent)) = rel.split_last() else {
            return Ok(false);
        };
        let parent = self.open_dir(parent)?;
        let path = safe_child(&parent.path, name)?;
        match std::fs::create_dir(&path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                match existing(&parent, name)? {
                    Existing::Dir => Ok(false),
                    _ => Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "exists and is not a directory (symlinks and junctions are never followed)",
                    )),
                }
            }
            Err(err) => Err(err),
        }
    }
}

fn safe_child(parent: &Path, name: &str) -> io::Result<PathBuf> {
    validate_name(name)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    Ok(parent.join(name))
}

/// What `name` in `dir` is, without following a symlink or junction.
pub(crate) fn existing(dir: &DirHandle, name: &str) -> io::Result<Existing> {
    let path = safe_child(&dir.path, name)?;
    classify(std::fs::symlink_metadata(path))
}

/// Length and mtime (seconds since the epoch) of the regular file `name` in `dir`.
pub(crate) fn file_info(dir: &DirHandle, name: &str) -> io::Result<Option<(u64, u64)>> {
    let path = safe_child(&dir.path, name)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !is_reparse(&meta) && meta.is_file() => {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_secs());
            Ok(Some((meta.len(), mtime)))
        }
        Ok(_) => Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Creates `name` in `dir` for writing. `create_new` unless the user confirmed an overwrite.
pub(crate) fn create_file(
    dir: &DirHandle,
    name: &str,
    _mode: Mode,
    truncate_existing: bool,
) -> io::Result<File> {
    let path = safe_child(&dir.path, name)?;
    match existing(dir, name)? {
        Existing::Nothing => {}
        Existing::File if truncate_existing => {}
        Existing::Dir | Existing::Other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the target exists and is not a regular file",
            ));
        }
        Existing::File => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the target already exists",
            ));
        }
    }
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create(true)
        .truncate(truncate_existing)
        .create_new(!truncate_existing);
    open_regular(&path, &mut options)
}

/// Opens an existing `.part` for resume and returns its length.
pub(crate) fn open_for_resume(dir: &DirHandle, name: &str) -> io::Result<(File, u64)> {
    let path = safe_child(&dir.path, name)?;
    let meta = std::fs::symlink_metadata(&path)?;
    if is_reparse(&meta) || !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let file = open_regular(&path, OpenOptions::new().read(true).write(true))?;
    let len = file.metadata()?.len();
    Ok((file, len))
}

/// Opens `path` without following a symlink or junction planted after the checks above, and
/// keeps the handle only if it is a regular file.
fn open_regular(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    let file = options.custom_flags(OPEN_REPARSE_POINT).open(path)?;
    let meta = file.metadata()?;
    if is_reparse(&meta) || !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// Publishes `part` as `name`; without `replace`, an existing target is a conflict.
pub(crate) fn finish(dir: &DirHandle, part: &str, name: &str, replace: bool) -> io::Result<()> {
    let part = safe_child(&dir.path, part)?;
    let name_path = safe_child(&dir.path, name)?;
    if !replace {
        match existing(dir, name)? {
            Existing::Nothing => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the target already exists",
                ));
            }
        }
    }
    std::fs::rename(part, name_path)
}

/// Removes the file `name` in `dir`.
pub(crate) fn remove(dir: &DirHandle, name: &str) -> io::Result<()> {
    std::fs::remove_file(safe_child(&dir.path, name)?)
}

/// Free bytes available to the current user on the filesystem holding `dir`.
pub(crate) fn available_space(dir: &DirHandle) -> io::Result<u64> {
    fs4::available_space(&dir.path)
}

#[cfg(test)]
mod tests {

    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fogu-winfs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn creates_resumes_and_publishes_a_file() {
        let root = tempdir("publish");
        let dir = LocalDir::open(&root).unwrap();
        let mut file = create_file(dir.fd(), "a.part", Mode::from_raw_mode(0o644), false).unwrap();
        std::io::Write::write_all(&mut file, b"hello").unwrap();
        assert_eq!(file_info(dir.fd(), "a.part").unwrap().unwrap().0, 5);
        drop(file);
        let (file, len) = open_for_resume(dir.fd(), "a.part").unwrap();
        assert_eq!(len, 5);
        drop(file);
        finish(dir.fd(), "a.part", "a", false).unwrap();
        assert_eq!(std::fs::read(root.join("a")).unwrap(), b"hello");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rejects_reserved_and_alternate_stream_names() {
        let root = tempdir("names");
        let dir = LocalDir::open(&root).unwrap();
        for name in ["CON", "nul.txt", "a:b", "a\\b", "trail.", "trail "] {
            assert!(
                create_file(dir.fd(), name, Mode::from_raw_mode(0o644), false).is_err(),
                "{name} should be rejected"
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn refuses_to_descend_a_junction() {
        let root = tempdir("junction");
        let outside = tempdir("outside");
        let junction = root.join("link");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .status();
        if status.is_ok_and(|status| status.success()) {
            let dir = LocalDir::open(&root).unwrap();
            assert!(dir.open_dir(&["link".to_owned()]).is_err());
        }
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&outside).unwrap();
    }
}
