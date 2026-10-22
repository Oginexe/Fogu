//! Unix local writes: the destination directory is opened once and every file and directory
//! below it is reached from that fd one validated name at a time with `O_NOFOLLOW`, so a
//! pre-existing (or concurrently planted) local symlink can never redirect a write outside it.
//! Files are created `O_EXCL` (no silent overwrite) with mode `0644` (`0755` only with
//! `keep_executable_bit`; never setuid/setgid/sticky) and only become visible under their final
//! name by a rename that refuses to replace unless the user confirmed.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, RenameFlags};
use rustix::io::Errno;

use super::Existing;

/// The download destination root and every opened subdirectory.
#[derive(Debug)]
pub(crate) struct DirHandle {
    fd: OwnedFd,
}

/// The download destination, opened once.
#[derive(Debug)]
pub(crate) struct LocalDir {
    root: DirHandle,
}

impl LocalDir {
    /// Opens the user-chosen destination directory (following symlinks: the user picked it).
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let fd = rfs::openat(
            rfs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0),
        )?;
        Ok(Self {
            root: DirHandle { fd },
        })
    }

    /// The destination directory itself.
    pub(crate) fn fd(&self) -> &DirHandle {
        &self.root
    }

    /// Opens `rel` (validated names) below the root, refusing to traverse any symlink.
    pub(crate) fn open_dir(&self, rel: &[String]) -> io::Result<DirHandle> {
        let mut fd = rfs::openat(
            &self.root.fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0),
        )?;
        for name in rel {
            fd = open_subdir(&fd, name)?;
        }
        Ok(DirHandle { fd })
    }

    /// Creates the directory `rel` (its parent must exist; created by an earlier call). An
    /// existing directory is fine; an existing symlink or file of that name is an error.
    /// Returns whether it was created.
    pub(crate) fn make_dir(&self, rel: &[String]) -> io::Result<bool> {
        let Some((name, parent)) = rel.split_last() else {
            return Ok(false);
        };
        let parent = self.open_dir(parent)?;
        match rfs::mkdirat(&parent.fd, name.as_str(), Mode::from_raw_mode(0o755)) {
            Ok(()) => Ok(true),
            Err(Errno::EXIST) => match existing(&parent, name)? {
                Existing::Dir => Ok(false),
                _ => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "exists and is not a directory (symlinks are never followed)",
                )),
            },
            Err(err) => Err(err.into()),
        }
    }
}

fn open_subdir(dir: &OwnedFd, name: &str) -> io::Result<OwnedFd> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    Ok(rfs::openat(dir, name, flags, Mode::from_raw_mode(0))?)
}

/// What `name` in `dir` is, without following a symlink.
pub(crate) fn existing(dir: &DirHandle, name: &str) -> io::Result<Existing> {
    match rfs::statat(&dir.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => Existing::File,
            FileType::Directory => Existing::Dir,
            _ => Existing::Other,
        }),
        Err(Errno::NOENT) => Ok(Existing::Nothing),
        Err(err) => Err(err.into()),
    }
}

/// Length and mtime (seconds since the epoch) of the regular file `name` in `dir`, not
/// following a symlink; `None` when it is missing or not a regular file.
pub(crate) fn file_info(dir: &DirHandle, name: &str) -> io::Result<Option<(u64, u64)>> {
    match rfs::statat(&dir.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => Ok(Some((
            u64::try_from(stat.st_size).unwrap_or(0),
            u64::try_from(stat.st_mtime).unwrap_or(0),
        ))),
        Ok(_) | Err(Errno::NOENT) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// Creates `name` in `dir` for writing: `O_NOFOLLOW | O_CREAT | O_EXCL` (or, after a confirmed
/// overwrite, `O_NOFOLLOW | O_CREAT | O_TRUNC`). `O_NONBLOCK` keeps a planted FIFO from
/// blocking the open; anything but a regular file is refused afterwards.
pub(crate) fn create_file(
    dir: &DirHandle,
    name: &str,
    mode: Mode,
    truncate_existing: bool,
) -> io::Result<File> {
    let mut flags = OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    flags |= OFlags::CLOEXEC;
    flags |= if truncate_existing {
        OFlags::TRUNC
    } else {
        OFlags::EXCL
    };
    let fd = rfs::openat(&dir.fd, name, flags, mode)?;
    regular_only(fd)
}

/// Opens an existing `name` (a kept `.part`) to append from its end: `O_NOFOLLOW`, regular files
/// only. Returns the file and its length.
pub(crate) fn open_for_resume(dir: &DirHandle, name: &str) -> io::Result<(File, u64)> {
    let flags = OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = rfs::openat(&dir.fd, name, flags, Mode::from_raw_mode(0))?;
    let len = rfs::fstat(&fd)?.st_size;
    Ok((regular_only(fd)?, u64::try_from(len).unwrap_or(0)))
}

fn regular_only(fd: OwnedFd) -> io::Result<File> {
    let stat = rfs::fstat(&fd)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(File::from(fd))
}

/// Moves the finished `part` to `name` in `dir`. Without `replace` the rename fails if `name`
/// exists (`RENAME_NOREPLACE`, or `link` + `unlink` where the filesystem lacks it); with
/// `replace` an existing `name` is replaced (a symlink there is replaced itself, not followed).
pub(crate) fn finish(dir: &DirHandle, part: &str, name: &str, replace: bool) -> io::Result<()> {
    if replace {
        rfs::renameat(&dir.fd, part, &dir.fd, name)?;
    } else {
        match rfs::renameat_with(&dir.fd, part, &dir.fd, name, RenameFlags::NOREPLACE) {
            Ok(()) => {}
            Err(Errno::INVAL | Errno::NOSYS) => {
                rfs::linkat(&dir.fd, part, &dir.fd, name, AtFlags::empty())?;
                rfs::unlinkat(&dir.fd, part, AtFlags::empty())?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    // Makes the rename durable; best effort (some filesystems refuse fsync on a directory).
    let _best_effort = rfs::fsync(&dir.fd);
    Ok(())
}

/// Removes the file `name` in `dir` (a symlink would be removed itself).
pub(crate) fn remove(dir: &DirHandle, name: &str) -> io::Result<()> {
    Ok(rfs::unlinkat(&dir.fd, name, AtFlags::empty())?)
}

/// Free bytes for the unprivileged user on the filesystem holding `dir`.
pub(crate) fn available_space(dir: &DirHandle) -> io::Result<u64> {
    let stat = rfs::fstatvfs(&dir.fd)?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

#[cfg(test)]
#[path = "unix_tests.rs"]
mod tests;
