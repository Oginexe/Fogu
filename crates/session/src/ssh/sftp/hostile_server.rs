//! A hostile in-process SFTP server for tests (russh-sftp's server half over an in-memory
//! pipe; no SSH, no sshd) that lies about file sizes, sends hostile names, symlink loops, a
//! lying `realpath`, endless listings and oversized data replies, plus a scripted free-space
//! probe. Deletions are counted, never performed.
#![expect(
    clippy::unused_async_trait_impl,
    reason = "tests; the fake server implements async trait methods that need no await"
)]

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};

use super::disk_guard::{FreeSpace, Space};

pub(super) const MIB: u64 = 1024 * 1024;
/// An "endless" file: the server answers every read with data.
pub(super) const ENDLESS: u64 = u64::MAX;
/// Entries per `readdir` reply (the real server pages too).
const PAGE: usize = 100;

/// A file's byte at `offset` (so misplaced data is caught).
fn byte_at(offset: u64) -> u8 {
    (offset % 251) as u8
}

pub(super) fn content(len: u64) -> Vec<u8> {
    (0..len).map(byte_at).collect()
}

#[derive(Clone)]
pub(super) enum Node {
    Dir(Vec<String>),
    File {
        reported: Option<u64>,
        actual: u64,
    },
    /// A symlink: `readlink` says `target`, `stat` answers with `resolves_to`'s attributes
    /// (`None` = dangling).
    Symlink {
        target: String,
        resolves_to: Option<String>,
    },
}

/// A server that lies: `reported` is what stat/readdir say, `actual` what reads return.
#[derive(Clone, Default)]
pub(super) struct Hostile {
    nodes: HashMap<String, Node>,
    /// `readdir` position per open handle.
    listed: HashMap<String, usize>,
    /// `realpath` answers for a path (else the path itself).
    realpaths: HashMap<String, String>,
    /// Directories whose listing never ends (a fresh entry per reply).
    endless_dirs: Vec<String>,
    /// Every read reply carries one byte more than requested.
    oversize_reads: bool,
    /// `lstat`/`stat` say every path exists (as a file) — "keep both" can never find a name.
    everything_exists: bool,
    /// `remove`/`rmdir` calls (accepted, nothing deleted).
    removed: Arc<AtomicUsize>,
}

impl Hostile {
    pub(super) fn file(path: &str, reported: Option<u64>, actual: u64) -> Self {
        Self::default().with(path, Node::File { reported, actual })
    }

    pub(super) fn with(mut self, path: &str, node: Node) -> Self {
        self.nodes.insert(path.to_owned(), node);
        self
    }

    pub(super) fn realpath_of(mut self, path: &str, answer: &str) -> Self {
        self.realpaths.insert(path.to_owned(), answer.to_owned());
        self
    }

    pub(super) fn endless_dir(mut self, path: &str) -> Self {
        self.endless_dirs.push(path.to_owned());
        self.nodes.insert(path.to_owned(), Node::Dir(Vec::new()));
        self
    }

    pub(super) fn oversize_reads(mut self) -> Self {
        self.oversize_reads = true;
        self
    }

    pub(super) fn everything_exists(mut self) -> Self {
        self.everything_exists = true;
        self
    }

    /// Shared counter of `remove`/`rmdir` calls.
    pub(super) fn removals(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.removed)
    }

    fn attrs(&self, path: &str) -> Result<FileAttributes, StatusCode> {
        let Some(node) = self.nodes.get(path) else {
            return if self.everything_exists {
                Ok(file_attrs(Some(1)))
            } else {
                Err(StatusCode::NoSuchFile)
            };
        };
        Ok(match node {
            Node::Dir(_) => FileAttributes {
                permissions: Some(0o040_755),
                ..FileAttributes::default()
            },
            Node::File { reported, .. } => file_attrs(*reported),
            Node::Symlink { .. } => FileAttributes {
                permissions: Some(0o120_777),
                ..FileAttributes::default()
            },
        })
    }
}

fn file_attrs(size: Option<u64>) -> FileAttributes {
    FileAttributes {
        size,
        permissions: Some(0o100_644),
        ..FileAttributes::default()
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::new(),
    }
}

fn one_name(id: u32, name: &str) -> Name {
    Name {
        id,
        files: vec![File::new(name, FileAttributes::default())],
    }
}

impl russh_sftp::server::Handler for Hostile {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs {
            id,
            attrs: self.attrs(&path)?,
        })
    }

    /// Follows one level of symlink.
    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let attrs = match self.nodes.get(&path) {
            Some(Node::Symlink { resolves_to, .. }) => match resolves_to {
                Some(target) => self.attrs(target)?,
                None => return Err(StatusCode::NoSuchFile),
            },
            _ => self.attrs(&path)?,
        };
        Ok(Attrs { id, attrs })
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        match self.nodes.get(&path) {
            Some(Node::Symlink { target, .. }) => Ok(one_name(id, target)),
            _ => Err(StatusCode::NoSuchFile),
        }
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let answer = self.realpaths.get(&path).cloned().unwrap_or(path);
        Ok(one_name(id, &answer))
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        _pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.attrs(&filename)?;
        Ok(Handle {
            id,
            handle: filename,
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        self.attrs(&path)?;
        self.listed.insert(path.clone(), 0);
        Ok(Handle { id, handle: path })
    }

    /// One page per reply; an endless directory invents a new entry every time.
    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let at = *self.listed.get(&handle).unwrap_or(&0);
        if self.endless_dirs.contains(&handle) {
            self.listed.insert(handle, at + 1);
            return Ok(one_name(id, &format!("f{at}")));
        }
        let Some(Node::Dir(children)) = self.nodes.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        if at >= children.len() {
            return Err(StatusCode::Eof);
        }
        let mut files = Vec::new();
        for name in children.iter().skip(at).take(PAGE) {
            // A hostile name may not be a path at all; attributes of a file then.
            let attrs = self
                .attrs(&format!("{handle}/{name}"))
                .unwrap_or_else(|_| file_attrs(Some(3)));
            files.push(File::new(name, attrs));
        }
        self.listed.insert(handle, at + PAGE);
        Ok(Name { id, files })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let Some(Node::File { actual, .. }) = self.nodes.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        if offset >= *actual {
            return Err(StatusCode::Eof);
        }
        let extra = u64::from(self.oversize_reads);
        let end = offset
            .saturating_add(u64::from(len))
            .saturating_add(extra)
            .min(*actual);
        Ok(Data {
            id,
            data: (offset..end).map(byte_at).collect(),
        })
    }

    async fn remove(&mut self, id: u32, _filename: String) -> Result<Status, Self::Error> {
        self.removed.fetch_add(1, Ordering::Relaxed);
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, _path: String) -> Result<Status, Self::Error> {
        self.removed.fetch_add(1, Ordering::Relaxed);
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
        Ok(ok(id))
    }
}

/// Answers from a script; the last answer repeats.
pub(super) struct Scripted {
    answers: Vec<Space>,
    calls: AtomicUsize,
}

impl Scripted {
    pub(super) fn new(answers: &[Space]) -> Arc<Self> {
        Arc::new(Self {
            answers: answers.to_vec(),
            calls: AtomicUsize::new(0),
        })
    }

    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl FreeSpace for Scripted {
    fn probe(&self, _dir: &super::local_fs::DirHandle) -> io::Result<Space> {
        let i = self.calls.fetch_add(1, Ordering::Relaxed);
        let answer = self.answers.get(i).or(self.answers.last());
        Ok(*answer.unwrap())
    }
}

const PLENTY: Space = Space { avail: 1 << 50 };

pub(super) fn plenty() -> Arc<Scripted> {
    Scripted::new(&[PLENTY])
}
