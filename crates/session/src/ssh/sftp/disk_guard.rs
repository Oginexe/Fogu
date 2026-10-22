//! Disk-fill protection for downloads: a hostile server can
//! stream an endless file or report a huge size, so local disk use is bounded twice.
//!
//! - **Size cap** ([`FileCap`]): a file is capped at the size the server reported when the
//!   transfer was planned (no size = 0) unless `allow_growing_files`; `max_download_bytes`
//!   applies either way. The cap is checked *before* each chunk is written, so no byte past it
//!   ever reaches the disk.
//! - **Free-space reserve** ([`Guard`]): before a batch and before each file, the planned bytes
//!   plus the reserve must fit in the destination filesystem's free space; while writing, the
//!   free space is probed every [`CHECK_EVERY`] bytes and the file stops below the reserve.
//!
//! The probe is a [`FreeSpace`] handed to the engine (`statvfs` in production, scripted in
//! tests), never a global.

use std::fmt::Write as _;
use std::io;
use std::sync::Arc;

use super::local_fs::DirHandle;
use crate::sftp::SftpOptions;

/// Bytes written between two free-space probes during one file.
pub(crate) const CHECK_EVERY: u64 = 8 * 1024 * 1024;

/// Free bytes of a filesystem (for unprivileged users).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Space {
    pub(crate) avail: u64,
}

/// Reports the free space of the filesystem holding a directory.
pub(crate) trait FreeSpace: Send + Sync {
    fn probe(&self, dir: &DirHandle) -> io::Result<Space>;
}

/// The engine's probe.
pub(crate) type SpaceProbe = Arc<dyn FreeSpace>;

/// Free space of the destination filesystem (`fstatvfs` on Unix, `GetDiskFreeSpaceExW` on
/// Windows).
#[derive(Debug)]
pub(crate) struct Statvfs;

impl FreeSpace for Statvfs {
    fn probe(&self, dir: &DirHandle) -> io::Result<Space> {
        Ok(Space {
            avail: super::local_fs::available_space(dir)?,
        })
    }
}

/// Why a file has a byte limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapKind {
    /// The size the server reported.
    Reported,
    /// `max_download_bytes`.
    Configured,
}

/// The most bytes one downloaded file may have on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileCap {
    pub(crate) limit: u64,
    kind: CapKind,
}

impl FileCap {
    /// The cap of a file the server reported as `reported` bytes (`None` counts as 0);
    /// `None` = unlimited (growing files allowed, no `max_download_bytes`).
    pub(crate) fn of(opts: &SftpOptions, reported: Option<u64>) -> Option<Self> {
        let reported = (!opts.allow_growing_files).then(|| Self {
            limit: reported.unwrap_or(0),
            kind: CapKind::Reported,
        });
        let configured = opts.max_download_bytes.map(|limit| Self {
            limit,
            kind: CapKind::Configured,
        });
        match (reported, configured) {
            (Some(r), Some(c)) => Some(if c.limit < r.limit { c } else { r }),
            (r, c) => r.or(c),
        }
    }

    /// Whether a file of `len` bytes would pass the cap.
    pub(crate) fn allows(self, len: u64) -> bool {
        len <= self.limit
    }

    /// The (sanitized, fixed-wording) failure text when the server sends more.
    pub(crate) fn exceeded(self) -> String {
        match self.kind {
            CapKind::Reported => format!(
                "server sent more data than the size it reported ({} bytes); download stopped",
                self.limit
            ),
            CapKind::Configured => format!(
                "file exceeds the download limit ({} bytes, max_download_bytes); download stopped",
                self.limit
            ),
        }
    }
}

/// Free-space checks for one destination.
#[derive(Clone)]
pub(crate) struct Guard {
    probe: SpaceProbe,
    opts: SftpOptions,
}

impl Guard {
    pub(crate) fn new(probe: SpaceProbe, opts: &SftpOptions) -> Self {
        Self {
            probe,
            opts: opts.clone(),
        }
    }

    /// `Ok` if `needed` more bytes fit in `dir`'s filesystem above the reserve.
    pub(crate) fn fits(&self, dir: &DirHandle, needed: u64) -> Result<(), String> {
        let space = self.space(dir)?;
        let reserve = self.opts.free_space_reserve_bytes;
        if needed.saturating_add(reserve) <= space.avail {
            return Ok(());
        }
        let mut text = String::from("not enough local free space: ");
        let _infallible = write!(
            text,
            "needs {needed} bytes plus a reserve of {reserve} bytes, {} available",
            space.avail
        );
        Err(text)
    }

    /// `Ok` while `dir`'s filesystem still has the reserve free (checked during a write).
    pub(crate) fn above_reserve(&self, dir: &DirHandle) -> Result<(), String> {
        let space = self.space(dir)?;
        let reserve = self.opts.free_space_reserve_bytes;
        if space.avail >= reserve {
            return Ok(());
        }
        Err(format!(
            "local free space fell below the reserve ({reserve} bytes); download stopped"
        ))
    }

    /// Fails closed: a filesystem whose free space can't be read gets no download.
    fn space(&self, dir: &DirHandle) -> Result<Space, String> {
        self.probe
            .probe(dir)
            .map_err(|err| format!("cannot check local free space: {err}"))
    }
}

/// Counts written bytes and says when the next free-space probe is due.
#[derive(Debug, Default)]
pub(crate) struct Every {
    since: u64,
}

impl Every {
    /// Adds `n` bytes about to be written; `true` once [`CHECK_EVERY`] bytes accumulated.
    pub(crate) fn due(&mut self, n: u64) -> bool {
        self.since = self.since.saturating_add(n);
        if self.since >= CHECK_EVERY {
            self.since = 0;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests")]

    use super::super::local_fs::LocalDir;
    use super::*;

    #[test]
    fn file_cap_table() {
        let base = SftpOptions::default();
        let grow = SftpOptions {
            allow_growing_files: true,
            ..SftpOptions::default()
        };
        let max = |opts: &SftpOptions, m| SftpOptions {
            max_download_bytes: Some(m),
            ..opts.clone()
        };
        let limit = |opts: &SftpOptions, reported| FileCap::of(opts, reported).map(|c| c.limit);
        assert_eq!(limit(&base, Some(10)), Some(10));
        assert_eq!(limit(&base, None), Some(0), "no size counts as 0");
        assert_eq!(limit(&max(&base, 5), Some(10)), Some(5));
        assert_eq!(limit(&max(&base, 50), Some(10)), Some(10));
        assert_eq!(limit(&grow, Some(10)), None);
        assert_eq!(limit(&max(&grow, 5), Some(10)), Some(5));
        let reported = FileCap::of(&base, Some(7)).unwrap();
        assert!(reported.allows(7) && !reported.allows(8));
        assert_eq!(
            reported.exceeded(),
            "server sent more data than the size it reported (7 bytes); download stopped"
        );
        assert!(
            FileCap::of(&max(&grow, 5), None)
                .unwrap()
                .exceeded()
                .contains("max_download_bytes")
        );
    }

    #[test]
    fn statvfs_reads_the_temp_filesystem() {
        let dir = LocalDir::open(&std::env::temp_dir()).unwrap();
        let space = Statvfs.probe(dir.fd()).unwrap();
        assert!(space.avail > 0, "{space:?}");
    }

    #[test]
    fn checks_are_due_every_few_mebibytes() {
        let mut every = Every::default();
        assert!(!every.due(CHECK_EVERY - 1));
        assert!(every.due(1));
        assert!(!every.due(1));
        assert!(every.due(u64::MAX));
    }
}
