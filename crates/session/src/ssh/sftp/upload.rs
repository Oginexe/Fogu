//! Uploads: local walk (blocking, on the blocking pool) → remote directories first → files
//! streamed through a pipelined writer. Same symlink rules as downloads: a local symlink is sent
//! as its target's content only when the target is a regular file; symlinked directories are
//! never descended. Remote files are created with `EXCLUDE` unless the user confirmed an
//! overwrite, with the local permission bits minus setuid/setgid/sticky.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh_sftp::protocol::FileAttributes;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio_util::sync::CancellationToken;

use super::local_fs::validate_name;
use super::ops::join;
use super::remote::kind_of;
use super::transfer::{
    Ctx, Fatal, FileEnd, Progress, finish, numbered, on_existing, resume_plausible, run_jobs,
};
use crate::sftp::{
    ConflictKind, EntryKind, KEEP_BOTH_MAX, NameError, OverwritePolicy, SftpEvent, SftpOptions,
    SkipReason, TransferReport,
};

/// Permission bits reported for a local file. Windows has no POSIX mode: use the usual 0644
/// default; the remote side applies its own umask anyway.
fn local_mode(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        meta.permissions().mode() & 0o777
    }
    #[cfg(windows)]
    {
        let _ = meta;
        0o644
    }
}

/// One file to send.
struct Job {
    local: PathBuf,
    remote: String,
    size: u64,
    /// Local modification time (resume plausibility).
    mtime: Option<u64>,
    mode: u32,
    overwrite: OverwritePolicy,
    resume: bool,
    progress: Arc<Progress>,
}

/// How the remote file is opened.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    /// `CREATE | EXCLUDE`: a new file.
    Create,
    /// `CREATE | TRUNCATE`: replace (confirmed overwrite).
    Truncate,
    /// `WRITE` from this offset: resume a shorter remote file.
    Append(u64),
}

/// What the local walk found: remote dirs to create (parents first), files, skips.
#[derive(Default)]
struct Plan {
    dirs: Vec<(String, String)>,
    files: Vec<(String, PathBuf, String, fs::Metadata)>,
    skipped: Vec<(String, SkipReason)>,
}

/// Runs a whole `Upload` command and sends its events.
pub(crate) async fn upload(
    ctx: Ctx,
    local: Vec<PathBuf>,
    remote_dir: String,
    (overwrite, resume): (OverwritePolicy, bool),
) {
    let mut report = TransferReport::default();
    let result = run(&ctx, local, &remote_dir, (overwrite, resume), &mut report).await;
    finish(&ctx, result, report).await;
}

async fn run(
    ctx: &Ctx,
    roots: Vec<PathBuf>,
    remote_dir: &str,
    (overwrite, resume): (OverwritePolicy, bool),
    report: &mut TransferReport,
) -> Result<(), Fatal> {
    if kind_of(&ctx.remote.stat(remote_dir).await?) != EntryKind::Dir {
        return Err(Fatal("the destination is not a directory".into()));
    }
    let (opts, cancel, base) = (ctx.opts.clone(), ctx.cancel.clone(), remote_dir.to_owned());
    let plan = tokio::task::spawn_blocking(move || walk(&roots, &base, &opts, &cancel))
        .await
        .map_err(|_| Fatal("local walk failed".into()))??;
    for (rel, reason) in plan.skipped {
        report.skip(rel, reason);
    }
    for (rel, path) in &plan.dirs {
        match ctx.remote.mkdir(path).await {
            Ok(()) => report.dirs_created += 1,
            Err(err) => match ctx.remote.lstat(path).await {
                Ok(attrs) if kind_of(&attrs) == EntryKind::Dir => {}
                _ => report.fail(rel.clone(), err.message),
            },
        }
    }
    let total = plan
        .files
        .iter()
        .map(|(_, _, _, m)| m.len())
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
        .map(|(rel, local, remote, meta)| {
            let job = Job {
                local,
                remote,
                size: meta.len(),
                mtime: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
                mode: local_mode(&meta),
                overwrite,
                resume,
                progress: Arc::clone(&progress),
            };
            (rel, job)
        })
        .collect();
    run_jobs(ctx, jobs, report, |ctx, job| async move {
        send(&ctx, job).await
    })
    .await;
    Ok(())
}

/// The local name of `path` as a valid remote name.
fn local_name(path: &Path) -> Result<String, NameError> {
    let name = path
        .file_name()
        .ok_or(NameError::Empty)?
        .to_str()
        .ok_or(NameError::Invalid)?;
    validate_name(name).map(str::to_owned)
}

/// Iterative local walk with the depth/entry caps (runs on the blocking pool).
fn walk(
    roots: &[PathBuf],
    remote_dir: &str,
    opts: &SftpOptions,
    cancel: &CancellationToken,
) -> Result<Plan, Fatal> {
    let mut plan = Plan::default();
    let mut queue = std::collections::VecDeque::new();
    for root in roots {
        match local_name(root) {
            Ok(name) => classify(
                &mut plan,
                &mut queue,
                root.clone(),
                name.clone(),
                join(remote_dir, &name),
                0,
            ),
            Err(err) => plan
                .skipped
                .push((root.display().to_string(), SkipReason::InvalidName(err))),
        }
    }
    let mut seen = 0_usize;
    while let Some((dir, rel, remote, depth)) = queue.pop_front() {
        if cancel.is_cancelled() {
            break;
        }
        if depth >= opts.max_walk_depth {
            return Err(Fatal(
                "directory tree too deep; nothing was transferred".into(),
            ));
        }
        let entries = fs::read_dir(&dir).map_err(|e| Fatal(format!("{rel}: {e}")))?;
        for entry in entries {
            let entry = entry.map_err(|e| Fatal(format!("{rel}: {e}")))?;
            seen += 1;
            if seen > opts.max_walk_entries {
                return Err(Fatal("too many files; nothing was transferred".into()));
            }
            let path = entry.path();
            match local_name(&path) {
                Ok(name) => {
                    let (child_rel, child_remote) = (format!("{rel}/{name}"), join(&remote, &name));
                    classify(
                        &mut plan,
                        &mut queue,
                        path,
                        child_rel,
                        child_remote,
                        depth + 1,
                    );
                }
                Err(err) => plan.skipped.push((
                    format!(
                        "{rel}/{}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    SkipReason::InvalidName(err),
                )),
            }
        }
    }
    Ok(plan)
}

type Queue = std::collections::VecDeque<(PathBuf, String, String, usize)>;

/// Sorts one local entry (`lstat`) into the plan.
fn classify(
    plan: &mut Plan,
    queue: &mut Queue,
    path: PathBuf,
    rel: String,
    remote: String,
    depth: usize,
) {
    let Ok(meta) = fs::symlink_metadata(&path) else {
        plan.skipped.push((rel, SkipReason::SymlinkNotFile));
        return;
    };
    let kind = meta.file_type();
    if kind.is_dir() {
        plan.dirs.push((rel.clone(), remote.clone()));
        queue.push_back((path, rel, remote, depth));
    } else if kind.is_file() {
        plan.files.push((rel, path, remote, meta));
    } else if kind.is_symlink() {
        match fs::metadata(&path) {
            Ok(target) if target.is_file() => plan.files.push((rel, path, remote, target)),
            Ok(target) if target.is_dir() => plan.skipped.push((rel, SkipReason::SymlinkToDir)),
            _ => plan.skipped.push((rel, SkipReason::SymlinkNotFile)),
        }
    } else {
        plan.skipped.push((rel, SkipReason::Special));
    }
}

/// Uploads one file; a remote file this run created (or truncated) is removed on
/// failure/cancel unless `keep_partial` (a resumed one is never removed).
async fn send(ctx: &Ctx, job: Job) -> FileEnd {
    let (target, open) = match target(ctx, &job).await {
        Ok(chosen) => chosen,
        Err(end) => return end,
    };
    let mut input = match tokio::fs::File::open(&job.local).await {
        Ok(file) => file,
        Err(err) => return FileEnd::Failed(err.to_string()),
    };
    let offset = if let Open::Append(offset) = open {
        offset
    } else {
        0
    };
    let opened = if matches!(open, Open::Append(_)) {
        ctx.remote.open_append(&target).await
    } else {
        let truncate = open == Open::Truncate;
        ctx.remote.open_write(&target, job.mode, truncate).await
    };
    let handle = match opened {
        Ok(handle) => handle,
        // Created meanwhile (EXCLUDE): same as finding it in the check above.
        Err(_)
            if open == Open::Create
                && matches!(ctx.remote.try_lstat(&target).await, Ok(Some(_))) =>
        {
            return match on_existing(job.overwrite, ConflictKind::Exists) {
                Err(end) => end,
                Ok(()) => FileEnd::Failed("the target appeared during the upload".into()),
            };
        }
        Err(err) => return FileEnd::Failed(err.message),
    };
    let result = copy(ctx, &job, &mut input, &handle, offset).await;
    let closed = ctx.remote.close_handle(handle).await;
    let end = match (result, closed) {
        (Ok(Some(bytes)), Ok(())) => return FileEnd::Done { bytes },
        (Ok(Some(_)), Err(err)) => FileEnd::Failed(format!("close: {}", err.message)),
        (Ok(None), _) => FileEnd::Cancelled,
        (Err(message), _) => FileEnd::Failed(message),
    };
    tracing::debug!(size = job.size, "upload did not complete");
    if !ctx.opts.keep_partial && !matches!(open, Open::Append(_)) {
        let _best_effort = ctx.remote.remove_file(&target).await;
    }
    end
}

/// Where and how to write: the planned path (new, confirmed overwrite or resume), or under
/// "keep both" the first free name next to it.
async fn target(ctx: &Ctx, job: &Job) -> Result<(String, Open), FileEnd> {
    let attrs = match ctx.remote.try_lstat(&job.remote).await {
        Ok(None) => return Ok((job.remote.clone(), Open::Create)),
        Ok(Some(attrs)) => attrs,
        Err(err) => return Err(FileEnd::Failed(err.message)),
    };
    let remote_size = attrs.size.unwrap_or(u64::MAX);
    if job.resume && kind_of(&attrs) == EntryKind::File && remote_size <= job.size {
        return Ok((job.remote.clone(), Open::Append(remote_size)));
    }
    if job.overwrite == OverwritePolicy::KeepBoth {
        return free_name(ctx, &job.remote).await.map(|p| (p, Open::Create));
    }
    match on_existing(job.overwrite, ConflictKind::Exists) {
        Ok(()) => Ok((job.remote.clone(), Open::Truncate)),
        Err(FileEnd::Conflict(kind, _)) => Err(FileEnd::Conflict(kind, resumable(job, &attrs))),
        Err(end) => Err(end),
    }
}

/// The existing remote file looks like an earlier, interrupted upload of this one.
fn resumable(job: &Job, attrs: &FileAttributes) -> bool {
    kind_of(attrs) == EntryKind::File
        && attrs.size.is_some_and(|size| {
            resume_plausible(size, attrs.mtime.map(u64::from), job.size, job.mtime)
        })
}

/// "Keep both": the first `name (n)` next to `path` that does not exist on the server. Up to
/// [`KEEP_BOTH_MAX`] round trips (a server on which "everything exists" can stall each one for
/// the request timeout), so a cancel is honoured between them.
async fn free_name(ctx: &Ctx, path: &str) -> Result<String, FileEnd> {
    let (dir, name) = split_remote(path);
    for n in 1..=KEEP_BOTH_MAX {
        if ctx.cancel.is_cancelled() {
            return Err(FileEnd::Cancelled);
        }
        let Some(candidate) = numbered(name, n) else {
            break;
        };
        let candidate = join(dir, &candidate);
        match ctx.remote.try_lstat(&candidate).await {
            Ok(None) => return Ok(candidate),
            Ok(Some(_)) => {}
            Err(err) => return Err(FileEnd::Failed(err.message)),
        }
    }
    Err(FileEnd::Failed("no free name to keep both files".into()))
}

/// `(dir, name)` of a remote path built by `join` (`"/a"` → `("/", "a")`, `"a"` → `("", "a")`).
fn split_remote(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some(("", name)) if path.starts_with('/') => ("/", name),
        Some((dir, name)) => (dir, name),
        None => ("", path),
    }
}

/// Streams the local file from `offset` into `handle`; `Ok(None)` = cancelled.
async fn copy(
    ctx: &Ctx,
    job: &Job,
    input: &mut tokio::fs::File,
    handle: &str,
    offset: u64,
) -> Result<Option<u64>, String> {
    if offset > 0 {
        input
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| e.to_string())?;
        job.progress.resumed(offset);
    }
    let mut writer = ctx.remote.writer(handle, offset);
    let mut bytes = 0_u64;
    loop {
        if ctx.cancel.is_cancelled() {
            return Ok(None);
        }
        let mut buf = vec![0; ctx.remote.write_chunk];
        let n = input.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.truncate(n);
        writer.write(buf).await.map_err(|e| e.message)?;
        bytes += n as u64;
        job.progress.add(n as u64);
    }
    writer.finish().await.map_err(|e| e.message)?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn remote_paths_split() {
        assert_eq!(super::split_remote("/a"), ("/", "a"));
        assert_eq!(super::split_remote("/d/a"), ("/d", "a"));
        assert_eq!(super::split_remote("d/a"), ("d", "a"));
        assert_eq!(super::split_remote("a"), ("", "a"));
    }
}
