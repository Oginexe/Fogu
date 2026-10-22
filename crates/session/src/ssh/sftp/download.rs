//! Downloads: remote walk → job list → streamed writes into `<name>.part` below the destination
//! directory fd → `RENAME_NOREPLACE` to `<name>`. Symlink rules: entries are `lstat`ed;
//! a symlink is downloaded as its target's content only when the target is a regular file,
//! symlinked directories are never descended (loops and escapes), and both are listed in the
//! report. Every remote name is validated before it becomes a local component.
//!
//! Disk-fill protection (`disk_guard.rs`): each file is capped at the size the server reported
//! when the transfer was planned (checked before every chunk is written), and the batch, each
//! file and every few MiB of writing must leave the free-space reserve on the destination.

use std::collections::VecDeque;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::Arc;

use russh_sftp::protocol::FileAttributes;
use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};

use super::disk_guard::{Every, FileCap, Guard};
use super::local_fs::{self, DirHandle, Existing, LocalDir, validate_name};
use super::ops::{WalkBudget, join, last_component};
use super::remote::kind_of;
use super::transfer::{
    Ctx, Fatal, FileEnd, Progress, finish, numbered, on_existing, resume_plausible, run_jobs,
};
use crate::sftp::{
    ConflictKind, EntryKind, KEEP_BOTH_MAX, OverwritePolicy, SftpEvent, SkipReason, TransferReport,
};

/// One file to fetch.
struct Job {
    remote: String,
    /// Local path below the destination: validated names, the last one is the file.
    rel: Vec<String>,
    /// Size the server reported when the walk ran (none = 0).
    size: u64,
    /// Remote modification time, if reported (resume plausibility).
    mtime: Option<u32>,
    /// Most bytes the local file may have (`None` = growing files allowed, no hard limit).
    cap: Option<FileCap>,
    mode: Option<u32>,
    overwrite: OverwritePolicy,
    resume: bool,
    dest: Arc<LocalDir>,
    guard: Arc<Guard>,
    progress: Arc<Progress>,
}

/// What the walk found.
#[derive(Default)]
struct Plan {
    dirs: Vec<Vec<String>>,
    files: Vec<(String, Vec<String>, FileAttributes)>,
}

/// Runs a whole `Download` command and sends its events.
pub(crate) async fn download(
    ctx: Ctx,
    remote: Vec<String>,
    local_dir: PathBuf,
    overwrite: OverwritePolicy,
    resume: bool,
) {
    let mut report = TransferReport::default();
    let result = run(&ctx, remote, &local_dir, overwrite, resume, &mut report).await;
    finish(&ctx, result, report).await;
}

async fn run(
    ctx: &Ctx,
    roots: Vec<String>,
    local_dir: &std::path::Path,
    overwrite: OverwritePolicy,
    resume: bool,
    report: &mut TransferReport,
) -> Result<(), Fatal> {
    let dest = LocalDir::open(local_dir)
        .map_err(|e| Fatal(format!("cannot open the destination directory: {e}")))?;
    let dest = Arc::new(dest);
    let plan = walk(ctx, roots, report).await?;
    let guard = Arc::new(Guard::new(Arc::clone(&ctx.space), &ctx.opts));
    let planned = plan
        .files
        .iter()
        .map(|(_, _, a)| planned_size(&ctx.opts, a.size))
        .fold(0, u64::saturating_add);
    guard.fits(dest.fd(), planned).map_err(Fatal)?;
    for rel in &plan.dirs {
        match dest.make_dir(rel) {
            Ok(created) => report.dirs_created += u64::from(created),
            Err(err) => report.fail(rel.join("/"), err.to_string()),
        }
    }
    // Reported sizes are server data: two files "of" u64::MAX must not overflow.
    let total = plan
        .files
        .iter()
        .map(|(_, _, a)| a.size.unwrap_or(0))
        .fold(0, u64::saturating_add);
    let queued = SftpEvent::TransferQueued {
        id: ctx.id,
        files: plan.files.len() as u64,
        total,
    };
    let _gone = ctx.events.send(queued).await;
    let progress = Progress::new(ctx, total);
    let jobs = plan
        .files
        .into_iter()
        .map(|(remote, rel, attrs)| {
            let job = Job {
                remote,
                size: attrs.size.unwrap_or(0),
                mtime: attrs.mtime,
                cap: FileCap::of(&ctx.opts, attrs.size),
                mode: attrs.permissions,
                rel,
                overwrite,
                resume,
                dest: Arc::clone(&dest),
                guard: Arc::clone(&guard),
                progress: Arc::clone(&progress),
            };
            (job.rel.join("/"), job)
        })
        .collect();
    run_jobs(ctx, jobs, report, |ctx, job| async move {
        fetch(&ctx, job).await
    })
    .await;
    Ok(())
}

/// Bytes a file is expected to take locally: its reported size, at most `max_download_bytes`
/// (a larger file is refused before it starts).
fn planned_size(opts: &crate::sftp::SftpOptions, reported: Option<u64>) -> u64 {
    let size = reported.unwrap_or(0);
    opts.max_download_bytes.map_or(size, |max| size.min(max))
}

/// Iterative remote walk with the depth/entry caps; directories come out parents first.
async fn walk(ctx: &Ctx, roots: Vec<String>, report: &mut TransferReport) -> Result<Plan, Fatal> {
    let mut plan = Plan::default();
    let mut queue = VecDeque::new();
    for root in roots {
        let name = last_component(&root).to_owned();
        if let Err(err) = validate_name(&name) {
            report.skip(name, SkipReason::InvalidName(err));
            continue;
        }
        match ctx.remote.lstat(&root).await {
            Ok(attrs) => {
                classify(ctx, &mut plan, &mut queue, root, vec![name], attrs, report).await;
            }
            Err(err) => report.fail(name, err.message),
        }
    }
    let mut budget = WalkBudget::new(&ctx.opts);
    while let Some((dir, rel)) = queue.pop_front() {
        if ctx.cancel.is_cancelled() {
            return Ok(plan);
        }
        if rel.len() > ctx.opts.max_walk_depth {
            return Err(Fatal(
                "directory tree too deep; nothing was transferred".into(),
            ));
        }
        let (entries, truncated) = ctx
            .remote
            .read_dir(&dir, ctx.opts.max_listing_entries)
            .await?;
        if truncated {
            return Err(Fatal(
                "a directory is too large; nothing was transferred".into(),
            ));
        }
        for (name, attrs) in entries {
            let mut child_rel = rel.clone();
            if let Err(err) = validate_name(&name) {
                child_rel.push(name);
                report.skip(child_rel.join("/"), SkipReason::InvalidName(err));
                continue;
            }
            child_rel.push(name.clone());
            let path = join(&dir, &name);
            // The job keeps the remote path and the local components (≈ the same length).
            if budget.take(2 * path.len()).is_err() {
                return Err(Fatal("too many files; nothing was transferred".into()));
            }
            classify(ctx, &mut plan, &mut queue, path, child_rel, attrs, report).await;
        }
    }
    Ok(plan)
}

/// Sorts one `lstat`ed entry into the plan.
async fn classify(
    ctx: &Ctx,
    plan: &mut Plan,
    queue: &mut VecDeque<(String, Vec<String>)>,
    path: String,
    rel: Vec<String>,
    attrs: FileAttributes,
    report: &mut TransferReport,
) {
    match kind_of(&attrs) {
        EntryKind::Dir => {
            plan.dirs.push(rel.clone());
            queue.push_back((path, rel));
        }
        EntryKind::File => plan.files.push((path, rel, attrs)),
        EntryKind::Symlink => match ctx.remote.stat(&path).await {
            Ok(target) if kind_of(&target) == EntryKind::File => {
                plan.files.push((path, rel, target));
            }
            Ok(target) if kind_of(&target) == EntryKind::Dir => {
                report.skip(rel.join("/"), SkipReason::SymlinkToDir);
            }
            _ => report.skip(rel.join("/"), SkipReason::SymlinkNotFile),
        },
        EntryKind::Other => report.skip(rel.join("/"), SkipReason::Special),
    }
}

/// Downloads one file; a `.part` this run created is removed on failure/cancel unless
/// `keep_partial` (a `.part` resumed from an earlier run is never deleted).
async fn fetch(ctx: &Ctx, job: Job) -> FileEnd {
    let Some((name, parent)) = job.rel.split_last() else {
        return FileEnd::Failed("empty path".into());
    };
    if job.cap.is_some_and(|cap| !cap.allows(job.size)) {
        return FileEnd::Failed(format!(
            "the file ({} bytes) is larger than the download limit (max_download_bytes); \
             not downloaded",
            job.size
        ));
    }
    let dir = match job.dest.open_dir(parent) {
        Ok(dir) => dir,
        Err(err) => return FileEnd::Failed(format!("destination directory: {err}")),
    };
    let kept;
    let name = if job.overwrite == OverwritePolicy::KeepBoth {
        match free_name(&dir, name) {
            Ok(free) => {
                kept = free;
                kept.as_str()
            }
            Err(end) => return end,
        }
    } else {
        name.as_str()
    };
    let Some(part) = local_fs::part_name(name) else {
        return FileEnd::Failed("name too long for a .part file".into());
    };
    let replace = match local_fs::existing(&dir, name) {
        Ok(Existing::Nothing) => false,
        Ok(_) => match on_existing(job.overwrite, ConflictKind::Exists) {
            Ok(()) => true,
            Err(end) => return end,
        },
        Err(err) => return FileEnd::Failed(err.to_string()),
    };
    let keep_exec = ctx.opts.keep_executable_bit;
    let (file, offset, created) = match open_part(&job, &dir, &part, keep_exec) {
        Ok(opened) => opened,
        Err(end) => return end,
    };
    let end = match job.guard.fits(&dir, job.size.saturating_sub(offset)) {
        Ok(()) => stream(ctx, &job, file, offset, &dir).await,
        Err(message) => FileEnd::Failed(message),
    };
    let end = match end {
        FileEnd::Done { bytes } => match local_fs::finish(&dir, &part, name, replace) {
            Ok(()) => return FileEnd::Done { bytes },
            // Someone created the target meanwhile: keep the complete `.part`, report it.
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return FileEnd::Conflict(ConflictKind::Exists, false);
            }
            Err(err) => FileEnd::Failed(format!("rename: {err}")),
        },
        other => other,
    };
    // A resumed `.part` existed before this run: never delete what this run did not create.
    if !ctx.opts.keep_partial && created {
        let _best_effort = local_fs::remove(&dir, &part);
    }
    end
}

/// Creates (or, with `resume`, reopens) the `.part` file; returns it, the resume offset and
/// whether this run created (or truncated) it. A `.part` longer than the reported size (so
/// resuming would pass the cap) is left alone unless the user chose `Overwrite`.
fn open_part(
    job: &Job,
    dir: &DirHandle,
    part: &str,
    keep_exec: bool,
) -> Result<(std::fs::File, u64, bool), FileEnd> {
    let failed = |err: std::io::Error| FileEnd::Failed(format!("{part}: {err}"));
    let mode = local_fs::file_mode(job.mode, keep_exec);
    match local_fs::existing(dir, part).map_err(failed)? {
        Existing::Nothing => {
            let file = local_fs::create_file(dir, part, mode, false).map_err(failed)?;
            Ok((file, 0, true))
        }
        Existing::File if job.resume => {
            let (file, len) = local_fs::open_for_resume(dir, part).map_err(failed)?;
            // `.part` + remaining must stay within the cap; the cap is ≤ the reported size
            // unless growing files are allowed, and a `.part` longer than the remote file is
            // not a prefix of it either way.
            if len <= job.size && job.cap.is_none_or(|cap| cap.allows(len)) {
                return Ok((file, len, false));
            }
            if job.overwrite != OverwritePolicy::Overwrite {
                return Err(FileEnd::Failed(format!(
                    "{part} is longer than the size the server reported ({} bytes); not \
                     resumed (download again with overwrite to start over)",
                    job.size
                )));
            }
            file.set_len(0).map_err(failed)?;
            Ok((file, 0, true))
        }
        other => {
            if let Err(end) = on_existing(job.overwrite, ConflictKind::PartialExists) {
                let resumable = other == Existing::File
                    && job.overwrite == OverwritePolicy::Ask
                    && part_resumable(job, dir, part);
                return Err(match end {
                    FileEnd::Conflict(kind, _) => FileEnd::Conflict(kind, resumable),
                    end => end,
                });
            }
            let file = local_fs::create_file(dir, part, mode, true).map_err(failed)?;
            Ok((file, 0, true))
        }
    }
}

/// Whether the existing `.part` looks like an earlier, interrupted download of this file.
fn part_resumable(job: &Job, dir: &DirHandle, part: &str) -> bool {
    let Ok(Some((len, mtime))) = local_fs::file_info(dir, part) else {
        return false;
    };
    job.cap.is_none_or(|cap| cap.allows(len))
        && resume_plausible(len, Some(mtime), job.size, job.mtime.map(u64::from))
}

/// "Keep both": `name` itself when neither it nor its `.part` exists, else the first free
/// `name (n)` (checked the same way, symlinks not followed).
fn free_name(dir: &DirHandle, name: &str) -> Result<String, FileEnd> {
    let free = |candidate: &str| -> std::io::Result<bool> {
        let Some(part) = local_fs::part_name(candidate) else {
            return Ok(false);
        };
        Ok(local_fs::existing(dir, candidate)? == Existing::Nothing
            && local_fs::existing(dir, &part)? == Existing::Nothing)
    };
    let failed = |err: std::io::Error| FileEnd::Failed(err.to_string());
    if free(name).map_err(failed)? {
        return Ok(name.to_owned());
    }
    for n in 1..=KEEP_BOTH_MAX {
        let Some(candidate) = numbered(name, n) else {
            break;
        };
        if free(&candidate).map_err(failed)? {
            return Ok(candidate);
        }
    }
    Err(FileEnd::Failed("no free name to keep both files".into()))
}

/// Why a stream stopped early.
enum Halt {
    Io(std::io::Error),
    /// Sanitized text (cap, free space, remote error).
    Stop(String),
}

impl From<std::io::Error> for Halt {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Copies the remote file from `offset` into `file`, then flushes and syncs it. Before each
/// chunk is written the file's cap is checked (nothing past it ever reaches the disk), and every
/// [`CHECK_EVERY`](super::disk_guard::CHECK_EVERY) bytes the free-space reserve of `dir`.
async fn stream(
    ctx: &Ctx,
    job: &Job,
    file: std::fs::File,
    offset: u64,
    dir: &DirHandle,
) -> FileEnd {
    let handle = match ctx.remote.open_read(&job.remote).await {
        Ok(handle) => handle,
        Err(err) => return FileEnd::Failed(err.message),
    };
    let mut out = tokio::fs::File::from_std(file);
    let mut bytes = 0_u64;
    let mut every = Every::default();
    let result = async {
        if offset > 0 {
            out.seek(SeekFrom::Start(offset)).await?;
            job.progress.resumed(offset);
        }
        let mut reader = ctx.remote.reader(&handle, offset);
        loop {
            let chunk = tokio::select! {
                biased;
                () = ctx.cancel.cancelled() => return Ok(false),
                chunk = reader.next() => chunk.map_err(|e| Halt::Stop(e.message))?,
            };
            let Some(data) = chunk else { break };
            let len = data.len() as u64;
            let after = offset.saturating_add(bytes).saturating_add(len);
            if let Some(cap) = job.cap
                && !cap.allows(after)
            {
                return Err(Halt::Stop(cap.exceeded()));
            }
            if every.due(len) {
                job.guard.above_reserve(dir).map_err(Halt::Stop)?;
            }
            out.write_all(&data).await?;
            bytes += len;
            job.progress.add(len);
        }
        out.flush().await?;
        out.sync_all().await?;
        Ok::<_, Halt>(true)
    }
    .await;
    // A read handle's close status carries nothing we need.
    let _closed = ctx.remote.close_handle(handle).await;
    match result {
        Ok(true) => FileEnd::Done { bytes },
        Ok(false) => FileEnd::Cancelled,
        Err(Halt::Stop(message)) => FileEnd::Failed(message),
        Err(Halt::Io(err)) => FileEnd::Failed(crate::sanitize_remote(&err.to_string(), 300, false)),
    }
}

#[cfg(test)]
#[path = "download_tests.rs"]
pub(super) mod tests;
