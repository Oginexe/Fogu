//! The transfers strip and the conflict queue. Pure state + the re-issue planner: a conflict's
//! path is the target relative to the transfer root (raw, built by the engine from validated
//! names); it is re-validated component by component here before it becomes a local path, so a
//! remote name can never pick a local path outside the directory the user chose.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fogu_session::sftp::{ConflictKind, OverwritePolicy, SkipReason, TransferId, TransferReport};
use fogu_session::{SftpCmd, display_name, validate_name};

use super::breadcrumb::join;

/// Download or upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Download,
    Upload,
}

/// Where a transfer came from and went to (to re-issue single files after a conflict).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Remote entries of `remote_dir` into `local_dir`.
    Download {
        remote_dir: String,
        local_dir: PathBuf,
    },
    /// Local paths into `remote_dir`.
    Upload {
        local: Vec<PathBuf>,
        remote_dir: String,
    },
}

/// Lifecycle of one transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferState {
    /// Sent; the engine is walking/planning.
    Planning,
    /// Copying.
    Running,
    /// Finished (see the counts).
    Done,
    /// Could not run, or the connection went away (sanitized message).
    Failed(String),
    /// Cancelled by the user.
    Cancelled,
}

/// One row of the transfers strip.
#[derive(Clone, Debug)]
pub struct Transfer {
    pub id: TransferId,
    pub direction: Direction,
    /// What is being transferred (sanitized).
    pub label: String,
    pub origin: Origin,
    pub files: u64,
    pub bytes: u64,
    pub total: u64,
    /// Bytes per second.
    pub rate: u64,
    pub state: TransferState,
    /// Completed / failed / skipped counts from the report.
    pub done_files: u64,
    pub failed: u64,
    pub skipped: u64,
    /// When it reached a final state.
    pub finished: Option<Instant>,
    /// A single-file download: the local file the finished toast's "Open" button opens.
    pub open_file: Option<PathBuf>,
    /// "Download and open": open `open_file` as soon as it is complete.
    pub open_when_done: bool,
}

impl Transfer {
    /// A transfer that was just sent.
    pub fn new(id: TransferId, direction: Direction, label: String, origin: Origin) -> Self {
        Self {
            id,
            direction,
            label,
            origin,
            files: 0,
            bytes: 0,
            total: 0,
            rate: 0,
            state: TransferState::Planning,
            done_files: 0,
            failed: 0,
            skipped: 0,
            finished: None,
            open_file: None,
            open_when_done: false,
        }
    }

    /// Still planning or running.
    pub fn is_active(&self) -> bool {
        matches!(self.state, TransferState::Planning | TransferState::Running)
    }

    /// Progress 0..=1 (0 while the total is unknown).
    pub fn fraction(&self) -> f32 {
        if self.state == TransferState::Done && self.failed == 0 && self.skipped == 0 {
            return 1.0;
        }
        if self.total == 0 {
            return 0.0;
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            reason = "a progress bar ratio; exactness beyond 2^52 bytes is irrelevant"
        )]
        let ratio = (self.bytes as f64 / self.total as f64).clamp(0.0, 1.0) as f32;
        ratio
    }
}

/// The transfers list, newest last.
#[derive(Clone, Debug, Default)]
pub struct Transfers {
    pub items: Vec<Transfer>,
    pub collapsed: bool,
}

impl Transfers {
    pub fn get_mut(&mut self, id: TransferId) -> Option<&mut Transfer> {
        self.items.iter_mut().find(|t| t.id == id)
    }

    pub fn get(&self, id: TransferId) -> Option<&Transfer> {
        self.items.iter().find(|t| t.id == id)
    }

    pub fn push(&mut self, transfer: Transfer) {
        self.items.push(transfer);
    }

    pub fn queued(&mut self, id: TransferId, files: u64, total: u64) {
        if let Some(t) = self.get_mut(id).filter(|t| t.is_active()) {
            t.files = files;
            t.total = total;
            t.state = TransferState::Running;
        }
    }

    pub fn progress(&mut self, id: TransferId, bytes: u64, total: u64, rate: u64) {
        if let Some(t) = self.get_mut(id).filter(|t| t.is_active()) {
            t.bytes = bytes;
            t.total = total;
            t.rate = rate;
            t.state = TransferState::Running;
        }
    }

    /// A final event; `None` for a transfer we don't know (or already final).
    pub fn finish(
        &mut self,
        id: TransferId,
        state: TransferState,
        report: &TransferReport,
        now: Instant,
    ) -> Option<&Transfer> {
        let t = self.get_mut(id).filter(|t| t.is_active())?;
        // Progress events are lossy and a resume reports only the new bytes: a clean finish
        // shows the whole size.
        let clean =
            state == TransferState::Done && report.failed.is_empty() && report.skipped.is_empty();
        t.bytes = if clean {
            t.total.max(report.bytes)
        } else {
            t.bytes.max(report.bytes)
        };
        t.done_files = report.files_done;
        t.failed = report.failed.len() as u64;
        t.skipped = report.skipped.len() as u64;
        t.state = state;
        t.rate = 0;
        t.finished = Some(now);
        Some(t)
    }

    /// The connection went away: every active transfer failed.
    pub fn fail_active(&mut self, message: &str, now: Instant) {
        for t in self.items.iter_mut().filter(|t| t.is_active()) {
            t.state = TransferState::Failed(message.to_owned());
            t.finished = Some(now);
        }
    }

    /// Drops finished transfers older than `linger`, except those `pinned` (a conflict of
    /// theirs is still waiting for an answer, which needs the transfer's origin); `true` when
    /// any remain finished (another sweep is due).
    pub fn sweep(&mut self, now: Instant, linger: Duration, pinned: &Conflicts) -> bool {
        self.items.retain(|t| {
            pinned.queue.iter().any(|c| c.transfer == t.id)
                || t.finished
                    .is_none_or(|f| now.saturating_duration_since(f) < linger)
        });
        self.items.iter().any(|t| t.finished.is_some())
    }

    /// "Clear": drops every finished transfer (except `pinned` ones, see [`Self::sweep`]).
    pub fn clear_finished(&mut self, pinned: &Conflicts) {
        self.items
            .retain(|t| t.is_active() || pinned.queue.iter().any(|c| c.transfer == t.id));
    }

    pub fn active_count(&self) -> usize {
        self.items.iter().filter(|t| t.is_active()).count()
    }
}

/// One file the engine skipped because its target exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub transfer: TransferId,
    /// Target relative to the transfer root (raw).
    pub path: String,
    pub kind: ConflictKind,
    /// The engine found resuming plausible (offer "Resume").
    pub resumable: bool,
}

/// The user's answer to a conflict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictChoice {
    Overwrite,
    Skip,
    /// Write under a free `name (n)` name.
    KeepBoth,
    /// Continue the partial file (only offered when the engine found it plausible).
    Resume,
}

impl ConflictChoice {
    /// How the chosen files are re-issued: (policy, resume); `None` = not at all.
    pub fn reissue_as(self) -> Option<(OverwritePolicy, bool)> {
        match self {
            Self::Overwrite => Some((OverwritePolicy::Overwrite, false)),
            Self::KeepBoth => Some((OverwritePolicy::KeepBoth, false)),
            Self::Resume => Some((OverwritePolicy::Ask, true)),
            Self::Skip => None,
        }
    }

    /// Suffix of a re-issued transfer's label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Overwrite => "overwrite",
            Self::KeepBoth => "keep both",
            Self::Resume => "resume",
            Self::Skip => "skip",
        }
    }
}

/// Conflicts waiting for an answer, oldest first; the first one is shown.
#[derive(Clone, Debug, Default)]
pub struct Conflicts {
    pub queue: VecDeque<Conflict>,
    /// "Apply to all" checkbox.
    pub apply_all: bool,
}

impl Conflicts {
    /// The conflict the dialog shows.
    pub fn current(&self) -> Option<&Conflict> {
        self.queue.front()
    }

    /// Answers the current conflict (all queued ones with "apply to all"); returns the
    /// conflicts to re-issue (none for `Skip`). "Resume" for all takes only the resumable
    /// ones: the others stay queued and are asked next.
    pub fn answer(&mut self, choice: ConflictChoice) -> Vec<Conflict> {
        let taken: Vec<Conflict> = match (self.apply_all, choice) {
            (true, ConflictChoice::Resume) => {
                let (resume, rest): (Vec<_>, Vec<_>) =
                    self.queue.drain(..).partition(|c| c.resumable);
                self.queue = rest.into();
                resume
            }
            (true, _) => self.queue.drain(..).collect(),
            (false, _) => self.queue.pop_front().into_iter().collect(),
        };
        if self.queue.is_empty() {
            self.apply_all = false;
        }
        match choice {
            ConflictChoice::Skip => Vec::new(),
            _ => taken,
        }
    }

    /// Drops the conflicts of transfers that no longer exist (connection rebound).
    pub fn clear(&mut self) {
        self.queue.clear();
        self.apply_all = false;
    }
}

/// The text the conflict dialog shows for `c` (sanitized).
pub fn conflict_text(c: &Conflict, direction: Direction) -> String {
    let name = display_name(&c.path);
    match (c.kind, direction) {
        (ConflictKind::PartialExists, _) => {
            format!("A partial download \u{201c}{name}.part\u{201d} already exists.")
        }
        (ConflictKind::Exists, Direction::Download) => {
            format!("\u{201c}{name}\u{201d} already exists in the local folder.")
        }
        (ConflictKind::Exists, Direction::Upload) => {
            format!("\u{201c}{name}\u{201d} already exists on the server.")
        }
    }
}

/// Splits a conflict path into validated components (all must be plain names).
fn components(rel: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = rel.split('/').collect();
    if parts.iter().all(|p| validate_name(p).is_ok()) {
        Some(parts)
    } else {
        None
    }
}

/// Commands that re-issue `rels` (conflicts of one transfer) with `overwrite` / `resume`, one
/// per target directory. A path with an invalid component, or an upload root we don't know, is
/// dropped (returned in the second list, sanitized for display).
pub fn reissue(
    origin: &Origin,
    rels: &[String],
    (overwrite, resume): (OverwritePolicy, bool),
) -> (Vec<SftpCmd>, Vec<String>) {
    let mut cmds: Vec<SftpCmd> = Vec::new();
    let mut rejected = Vec::new();
    for rel in rels {
        let Some(parts) = components(rel) else {
            rejected.push(display_name(rel));
            continue;
        };
        let Some((_, dirs)) = parts.split_last() else {
            continue;
        };
        match origin {
            Origin::Download {
                remote_dir,
                local_dir,
            } => {
                let local = dirs.iter().fold(local_dir.clone(), |p, d| p.join(d));
                let remote = join(remote_dir, rel);
                if let Some(SftpCmd::Download { remote: list, .. }) = cmds
                    .iter_mut()
                    .find(|c| matches!(c, SftpCmd::Download { local_dir: l, .. } if *l == local))
                {
                    list.push(remote);
                } else {
                    cmds.push(SftpCmd::Download {
                        remote: vec![remote],
                        local_dir: local,
                        overwrite,
                        resume,
                    });
                }
            }
            Origin::Upload { local, remote_dir } => {
                let Some((root, below)) = parts.split_first() else {
                    continue;
                };
                let source = local
                    .iter()
                    .find(|p| p.file_name().is_some_and(|n| n.to_str() == Some(root)));
                let Some(source) = source else {
                    rejected.push(display_name(rel));
                    continue;
                };
                let file = below.iter().fold(source.clone(), |p, c| p.join(c));
                let dir = dirs.iter().fold(remote_dir.clone(), |p, d| join(&p, d));
                if let Some(SftpCmd::Upload { local: list, .. }) = cmds
                    .iter_mut()
                    .find(|c| matches!(c, SftpCmd::Upload { remote_dir: r, .. } if *r == dir))
                {
                    list.push(file);
                } else {
                    cmds.push(SftpCmd::Upload {
                        local: vec![file],
                        remote_dir: dir,
                        overwrite,
                        resume,
                    });
                }
            }
        }
    }
    (cmds, rejected)
}

/// `true` when every directory between `base` and `dir` is a real directory (not a symlink):
/// a re-issued download only goes where the first run created directories itself.
pub fn real_subdir(base: &Path, dir: &Path) -> bool {
    let Ok(rest) = dir.strip_prefix(base) else {
        return false;
    };
    let mut at = base.to_path_buf();
    for part in rest.components() {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_dir() => {}
            _ => return false,
        }
    }
    true
}

/// One-line summary of a finished transfer's report for a toast (sanitized, short).
pub fn report_summary(report: &TransferReport) -> String {
    let mut parts = vec![format!("{} file(s)", report.files_done)];
    let conflicts = report
        .skipped
        .iter()
        .filter(|s| matches!(s.reason, SkipReason::Exists(_)))
        .count();
    let skipped = report.skipped.len() - conflicts;
    if conflicts > 0 {
        parts.push(format!("{conflicts} already existed"));
    }
    if skipped > 0 {
        parts.push(format!("{skipped} skipped"));
    }
    if !report.failed.is_empty() {
        let first = report.failed.first().map_or(String::new(), |f| {
            format!(" ({}: {})", display_name(&f.path), f.message)
        });
        parts.push(format!("{} failed{first}", report.failed.len()));
    }
    parts.join(", ")
}

#[cfg(test)]
#[path = "transfers_tests.rs"]
mod tests;
