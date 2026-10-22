//! What downloads (`download.rs`) and uploads (`upload.rs`) share: the task context, throttled
//! progress, the per-connection file slots (at most `max_parallel_files` files stream at once),
//! per-file outcomes and the final event.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::disk_guard::SpaceProbe;
use super::remote::{Remote, RemoteError};
use crate::sftp::{
    ConflictKind, Failed, OverwritePolicy, REPORT_MAX_ITEMS, SftpEvent, SftpOptions, SkipReason,
    Skipped, TransferId, TransferReport,
};

/// Minimum time between two progress events of one transfer (~10/s).
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Everything a transfer task needs.
#[derive(Clone)]
pub(crate) struct Ctx {
    pub(crate) id: TransferId,
    pub(crate) remote: Arc<Remote>,
    pub(crate) events: Sender<SftpEvent>,
    pub(crate) cancel: CancellationToken,
    /// Per-connection file slots (`max_parallel_files`).
    pub(crate) slots: Arc<Semaphore>,
    pub(crate) opts: SftpOptions,
    /// Local free-space probe (downloads' disk-fill guard).
    pub(crate) space: SpaceProbe,
}

/// A transfer that could not run: sanitized text.
pub(crate) struct Fatal(pub(crate) String);

impl From<RemoteError> for Fatal {
    fn from(err: RemoteError) -> Self {
        Self(err.message)
    }
}

/// How one file ended.
pub(crate) enum FileEnd {
    Done {
        bytes: u64,
    },
    /// The target exists and the policy is `Ask`; `true` = resuming is plausible.
    Conflict(ConflictKind, bool),
    Skipped(SkipReason),
    Failed(String),
    Cancelled,
}

/// Throttled, lossy progress events shared by the files of one transfer.
pub(crate) struct Progress {
    id: TransferId,
    events: Sender<SftpEvent>,
    start: Instant,
    /// (bytes done, total, last event, bytes resumed: counted as done but not in the rate).
    state: Mutex<(u64, u64, Instant, u64)>,
}

impl Progress {
    pub(crate) fn new(ctx: &Ctx, total: u64) -> Arc<Self> {
        let start = Instant::now();
        Arc::new(Self {
            id: ctx.id,
            events: ctx.events.clone(),
            start,
            state: Mutex::new((0, total, start, 0)),
        })
    }

    /// Bytes a resume starts from: done, but not transferred now (kept out of the rate).
    pub(crate) fn resumed(&self, n: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.3 += n;
        }
        self.add(n);
    }

    /// Adds `n` done bytes; sends an event if the last one is ≥ 100 ms old.
    pub(crate) fn add(&self, n: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.0 += n;
        let now = Instant::now();
        if now.duration_since(state.2) < PROGRESS_INTERVAL {
            return;
        }
        state.2 = now;
        let secs = now.duration_since(self.start).as_secs_f64().max(0.001);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            reason = "a rate estimate"
        )]
        let rate = (state.0.saturating_sub(state.3) as f64 / secs) as u64;
        let event = SftpEvent::TransferProgress {
            id: self.id,
            bytes: state.0,
            total: state.1,
            rate,
        };
        // Lossy on purpose: a lagging UI must not slow the transfer down.
        let _full = self.events.try_send(event);
    }
}

/// Runs the files of `jobs` with at most `slots` at a time per connection, recording each
/// outcome in `report`. Stops starting new files once cancelled.
pub(crate) async fn run_jobs<J, F>(
    ctx: &Ctx,
    jobs: Vec<(String, J)>,
    report: &mut TransferReport,
    run: impl Fn(Ctx, J) -> F,
) where
    F: Future<Output = FileEnd> + Send + 'static,
{
    let mut running: JoinSet<(String, FileEnd)> = JoinSet::new();
    for (path, job) in jobs {
        let permit = tokio::select! {
            biased;
            () = ctx.cancel.cancelled() => break,
            permit = Arc::clone(&ctx.slots).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_closed) => break,
            },
        };
        let file = run(ctx.clone(), job);
        running.spawn(async move {
            let end = file.await;
            drop(permit);
            (path, end)
        });
        while let Some(done) = running.try_join_next() {
            record(ctx, report, done).await;
        }
    }
    while let Some(done) = running.join_next().await {
        record(ctx, report, done).await;
    }
}

async fn record(
    ctx: &Ctx,
    report: &mut TransferReport,
    done: Result<(String, FileEnd), tokio::task::JoinError>,
) {
    let Ok((path, end)) = done else {
        report.fail(String::new(), "transfer task failed".into());
        return;
    };
    match end {
        FileEnd::Done { bytes } => {
            report.files_done += 1;
            report.bytes += bytes;
        }
        FileEnd::Conflict(kind, resumable) => {
            let conflict = SftpEvent::Conflict {
                id: ctx.id,
                path: path.clone(),
                kind,
                resumable,
            };
            let _gone = ctx.events.send(conflict).await;
            report.skip(path, SkipReason::Exists(kind));
        }
        FileEnd::Skipped(reason) => report.skip(path, reason),
        FileEnd::Failed(message) => report.fail(path, message),
        FileEnd::Cancelled => {}
    }
}

/// What an existing target means under `policy`: `Ok(())` = go ahead and replace it. Under
/// `KeepBoth` the free name was already chosen, so a target found now appeared meanwhile: it is
/// a conflict like under `Ask`.
pub(crate) fn on_existing(policy: OverwritePolicy, kind: ConflictKind) -> Result<(), FileEnd> {
    match policy {
        OverwritePolicy::Overwrite => Ok(()),
        OverwritePolicy::Ask | OverwritePolicy::KeepBoth => Err(FileEnd::Conflict(kind, false)),
        OverwritePolicy::Skip => Err(FileEnd::Skipped(SkipReason::Exists(kind))),
    }
}

/// Whether continuing a partial copy is plausible (SFTP v3 has no checksums):
/// the partial file is shorter than the source and was last written no earlier than the
/// source last changed. A missing time on either side leaves only the size check.
pub(crate) fn resume_plausible(
    partial_len: u64,
    partial_mtime: Option<u64>,
    source_len: u64,
    source_mtime: Option<u64>,
) -> bool {
    let fresh = match (partial_mtime, source_mtime) {
        (Some(partial), Some(source)) => partial >= source,
        _ => true,
    };
    partial_len < source_len && fresh
}

/// `name` numbered for "keep both": `report.pdf` → `report (n).pdf`, `notes` / `.bashrc` →
/// `notes (n)` / `.bashrc (n)`. `None` when the result is not a valid name (too long).
pub(crate) fn numbered(name: &str, n: u32) -> Option<String> {
    let out = match name.rfind('.') {
        Some(dot) if dot > 0 => {
            let (stem, ext) = name.split_at(dot);
            format!("{stem} ({n}){ext}")
        }
        _ => format!("{name} ({n})"),
    };
    super::local_fs::validate_name(&out).ok()?;
    Some(out)
}

/// Sends the transfer's final event.
pub(crate) async fn finish(ctx: &Ctx, result: Result<(), Fatal>, report: TransferReport) {
    let event = match result {
        _ if ctx.cancel.is_cancelled() => SftpEvent::TransferCancelled { id: ctx.id, report },
        Ok(()) => SftpEvent::TransferDone { id: ctx.id, report },
        Err(Fatal(message)) => SftpEvent::TransferFailed {
            id: ctx.id,
            message,
            report,
        },
    };
    let _gone = ctx.events.send(event).await;
}

impl TransferReport {
    pub(crate) fn skip(&mut self, path: String, reason: SkipReason) {
        if self.skipped.len() < REPORT_MAX_ITEMS {
            self.skipped.push(Skipped { path, reason });
        } else {
            self.omitted += 1;
        }
    }

    pub(crate) fn fail(&mut self, path: String, message: String) {
        if self.failed.len() < REPORT_MAX_ITEMS {
            self.failed.push(Failed { path, message });
        } else {
            self.omitted += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_lists_are_capped() {
        let mut report = TransferReport::default();
        for i in 0..REPORT_MAX_ITEMS + 5 {
            report.skip(i.to_string(), SkipReason::Special);
            report.fail(i.to_string(), "x".into());
        }
        assert_eq!(report.skipped.len(), REPORT_MAX_ITEMS);
        assert_eq!(report.failed.len(), REPORT_MAX_ITEMS);
        assert_eq!(report.omitted, 10);
    }

    #[test]
    fn resume_eligibility_table() {
        // (partial len, partial mtime, source len, source mtime, plausible)
        let rows = [
            (10, Some(200), 100, Some(100), true),
            (10, Some(100), 100, Some(100), true),
            (10, Some(99), 100, Some(100), false),
            (100, Some(200), 100, Some(100), false),
            (150, Some(200), 100, Some(100), false),
            (10, None, 100, Some(100), true),
            (10, Some(1), 100, None, true),
            (0, Some(200), 100, Some(100), true),
            (0, None, 0, None, false),
        ];
        for (plen, pt, slen, st, want) in rows {
            assert_eq!(
                resume_plausible(plen, pt, slen, st),
                want,
                "{plen} {pt:?} {slen} {st:?}"
            );
        }
    }

    #[test]
    fn keep_both_names() {
        assert_eq!(numbered("report.pdf", 1).as_deref(), Some("report (1).pdf"));
        assert_eq!(numbered("a.tar.gz", 2).as_deref(), Some("a.tar (2).gz"));
        assert_eq!(numbered("notes", 3).as_deref(), Some("notes (3)"));
        assert_eq!(numbered(".bashrc", 1).as_deref(), Some(".bashrc (1)"));
        #[cfg(unix)]
        assert_eq!(numbered("x.", 1).as_deref(), Some("x (1)."));
        // Windows trims a trailing dot, so this candidate is not a usable local name.
        #[cfg(windows)]
        assert_eq!(numbered("x.", 1), None);
        assert_eq!(numbered(&"a".repeat(252), 1), None);
    }
}
