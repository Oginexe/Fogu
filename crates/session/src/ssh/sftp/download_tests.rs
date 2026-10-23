//! Disk-fill protection against the hostile in-process SFTP server (`hostile_server.rs`): a
//! file streaming past its reported size, a huge reported size, no size at all, growing files,
//! resume past the cap, and the free-space reserve through a scripted probe.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::super::disk_guard::{CHECK_EVERY, Space, SpaceProbe};
use super::super::hostile_server::{ENDLESS, Hostile, MIB, Node, Scripted, content, plenty};
use super::super::remote::Remote;
use super::super::transfer::Ctx;
use super::download;
use crate::sftp::{CmdId, OverwritePolicy, SftpEvent, SftpOptions, TransferReport};

pub(in super::super) struct Tmp(pub(in super::super) PathBuf);

impl Tmp {
    pub(in super::super) fn new(label: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fogu-diskfill-{label}-{}-{n}", std::process::id()));
        let _stale = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub(in super::super) fn names(&self) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn len(&self, name: &str) -> u64 {
        std::fs::metadata(self.0.join(name)).unwrap().len()
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _best_effort = std::fs::remove_dir_all(&self.0);
    }
}

/// How one test download is set up.
struct Setup {
    opts: SftpOptions,
    space: SpaceProbe,
    roots: Vec<String>,
    overwrite: OverwritePolicy,
    resume: bool,
}

impl Setup {
    fn new(space: SpaceProbe) -> Self {
        Self {
            opts: SftpOptions::default(),
            space,
            roots: vec!["/f".into()],
            overwrite: OverwritePolicy::Ask,
            resume: false,
        }
    }
}

/// Runs one `Download` against `server` into `dest`; returns the final event.
async fn run(server: Hostile, setup: Setup, dest: &Path) -> SftpEvent {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    russh_sftp::server::run(server_io, server).await;
    let remote = Remote::over(client_io, &setup.opts).await.unwrap();
    let (events, mut rx) = mpsc::channel(4096);
    let ctx = Ctx {
        id: CmdId(1),
        remote: Arc::new(remote),
        events,
        cancel: CancellationToken::new(),
        slots: Arc::new(Semaphore::new(4)),
        opts: setup.opts,
        space: setup.space,
    };
    let dest = dest.to_owned();
    tokio::spawn(download(
        ctx,
        setup.roots,
        dest,
        setup.overwrite,
        setup.resume,
    ));
    loop {
        match rx.recv().await.unwrap() {
            SftpEvent::TransferQueued { .. } | SftpEvent::TransferProgress { .. } => {}
            end => return end,
        }
    }
}

pub(in super::super) fn report(end: SftpEvent) -> TransferReport {
    match end {
        SftpEvent::TransferDone { report, .. } => report,
        other => panic!("expected TransferDone, got {other:?}"),
    }
}

/// The single failure message of a finished transfer.
fn failure(end: SftpEvent) -> String {
    let report = report(end);
    assert_eq!(report.files_done, 0, "{report:?}");
    assert_eq!(report.failed.len(), 1, "{report:?}");
    report.failed.into_iter().next().unwrap().message
}

pub(in super::super) fn fatal(end: SftpEvent) -> String {
    match end {
        SftpEvent::TransferFailed { message, .. } => message,
        other => panic!("expected TransferFailed, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_cap_exact_reported_size_downloads() {
    let dest = Tmp::new("exact");
    let server = Hostile::file("/f", Some(300_000), 300_000);
    let done = report(run(server, Setup::new(plenty()), &dest.0).await);
    assert_eq!((done.files_done, done.bytes), (1, 300_000));
    assert_eq!(std::fs::read(dest.0.join("f")).unwrap(), content(300_000));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_cap_stops_a_server_streaming_past_its_reported_size() {
    for keep_partial in [false, true] {
        let dest = Tmp::new("endless");
        let server = Hostile::file("/f", Some(100_000), ENDLESS);
        let mut setup = Setup::new(plenty());
        setup.opts.keep_partial = keep_partial;
        let message = failure(run(server, setup, &dest.0).await);
        assert_eq!(
            message,
            "server sent more data than the size it reported (100000 bytes); download stopped"
        );
        if keep_partial {
            // Kept for a resume, but never a byte past the cap.
            assert_eq!(dest.names(), ["f.part"]);
            assert!(dest.len("f.part") <= 100_000);
        } else {
            assert_eq!(
                dest.names(),
                [] as [&str; 0],
                "the .part it created is removed"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_cap_refuses_a_huge_reported_size_before_writing() {
    let dest = Tmp::new("huge");
    // Default options: reserve = max(1 GiB, 5 % of 2 TiB).
    let disk = Scripted::new(&[Space { avail: 1 << 40 }]);
    let server = Hostile::file("/f", Some(1 << 60), ENDLESS);
    let message = fatal(run(server, Setup::new(disk), &dest.0).await);
    assert!(
        message.starts_with("not enough local free space: needs 1152921504606846976 bytes"),
        "{message}"
    );
    assert_eq!(dest.names(), [] as [&str; 0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_cap_missing_size_counts_as_zero() {
    let dest = Tmp::new("nosize");
    let server = Hostile::file("/f", None, 10);
    let message = failure(run(server, Setup::new(plenty()), &dest.0).await);
    assert!(message.contains("size it reported (0 bytes)"), "{message}");
    assert_eq!(dest.names(), [] as [&str; 0]);
    // An empty file without a size is fine.
    let server = Hostile::file("/f", None, 0);
    let done = report(run(server, Setup::new(plenty()), &dest.0).await);
    assert_eq!(done.files_done, 1);
    assert_eq!(dest.len("f"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_growing_files_allowed_fetches_the_whole_file() {
    let dest = Tmp::new("grow");
    let server = Hostile::file("/f", Some(1000), 300_000);
    let mut setup = Setup::new(plenty());
    setup.opts.allow_growing_files = true;
    let done = report(run(server.clone(), setup, &dest.0).await);
    assert_eq!(done.bytes, 300_000);
    assert_eq!(std::fs::read(dest.0.join("f")).unwrap(), content(300_000));
    // Off (default): the same file stops at 1000 bytes.
    let dest = Tmp::new("nogrow");
    let message = failure(run(server, Setup::new(plenty()), &dest.0).await);
    assert!(message.contains("(1000 bytes)"), "{message}");
    assert_eq!(dest.names(), [] as [&str; 0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_growing_files_still_obey_max_download_bytes() {
    let dest = Tmp::new("growmax");
    let mut setup = Setup::new(plenty());
    setup.opts.allow_growing_files = true;
    setup.opts.max_download_bytes = Some(200_000);
    setup.opts.keep_partial = true;
    let server = Hostile::file("/f", Some(1000), ENDLESS);
    let message = failure(run(server, setup, &dest.0).await);
    assert!(
        message.contains("download limit (200000 bytes"),
        "{message}"
    );
    assert!(dest.len("f.part") <= 200_000);
    // A reported size above the limit is refused before anything is created.
    let dest = Tmp::new("bigmax");
    let mut setup = Setup::new(plenty());
    setup.opts.max_download_bytes = Some(200_000);
    let server = Hostile::file("/f", Some(300_000), 300_000);
    let message = failure(run(server, setup, &dest.0).await);
    assert!(
        message.contains("larger than the download limit"),
        "{message}"
    );
    assert_eq!(dest.names(), [] as [&str; 0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_resume_respects_the_cap_and_keeps_the_part() {
    let dest = Tmp::new("resume");
    let part = dest.0.join("f.part");
    // A `.part` longer than the reported size: not resumed, left untouched.
    std::fs::write(&part, content(2000)).unwrap();
    let mut setup = Setup::new(plenty());
    setup.resume = true;
    let server = Hostile::file("/f", Some(1000), ENDLESS);
    let message = failure(run(server.clone(), setup, &dest.0).await);
    assert!(message.contains("not resumed"), "{message}");
    assert_eq!(std::fs::read(&part).unwrap(), content(2000));
    // A shorter `.part`, but the server sends past the cap: stopped at the cap, and the
    // pre-existing `.part` is never deleted (keep_partial is off).
    std::fs::write(&part, content(500)).unwrap();
    let mut setup = Setup::new(plenty());
    setup.resume = true;
    let message = failure(run(server, setup, &dest.0).await);
    assert!(message.contains("(1000 bytes)"), "{message}");
    assert_eq!(dest.names(), ["f.part"]);
    assert!(dest.len("f.part") <= 1000);
    // An honest server completes the resume.
    let mut setup = Setup::new(plenty());
    setup.resume = true;
    let honest = Hostile::file("/f", Some(1000), 1000);
    let done = report(run(honest, setup, &dest.0).await);
    assert_eq!(done.files_done, 1);
    assert_eq!(std::fs::read(dest.0.join("f")).unwrap(), content(1000));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_free_space_refuses_a_file_that_would_eat_the_reserve() {
    let dest = Tmp::new("nospace");
    // Default reserve 1 GiB; one byte short of 1.5 GiB free leaves room for less than
    // 0.5 GiB.
    let disk = Scripted::new(&[Space {
        avail: (1 << 30) + (1 << 29) - 1,
    }]);
    let server = Hostile::file("/f", Some(1 << 29), 1 << 29);
    let message = fatal(run(server, Setup::new(Arc::clone(&disk) as SpaceProbe), &dest.0).await);
    assert_eq!(
        message,
        "not enough local free space: needs 536870912 bytes plus a reserve of 1073741824 \
         bytes, 1610612735 available"
    );
    assert_eq!(dest.names(), [] as [&str; 0]);
    // Configurable: a smaller reserve lets it start (the server sends nothing past 10 bytes).
    let mut setup = Setup::new(disk);
    setup.opts.free_space_reserve_bytes = 0;
    let small = Hostile::file("/f", Some(10), 10);
    assert_eq!(report(run(small, setup, &dest.0).await).files_done, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_free_space_batch_uses_the_summed_size() {
    let dest = Tmp::new("batch");
    let file = |n| Node::File {
        reported: Some(n),
        actual: n,
    };
    let server = Hostile::default()
        .with("/d", Node::Dir(vec!["a".into(), "b".into(), "c".into()]))
        .with("/d/a", file(40))
        .with("/d/b", file(40))
        .with("/d/c", file(40));
    // Each file fits on its own, the three together don't.
    let disk = Scripted::new(&[Space { avail: 100 }]);
    let mut setup = Setup::new(Arc::clone(&disk) as SpaceProbe);
    setup.opts.free_space_reserve_bytes = 0;
    setup.roots = vec!["/d".into()];
    let message = fatal(run(server, setup, &dest.0).await);
    assert!(message.contains("needs 120 bytes"), "{message}");
    assert_eq!(dest.names(), [] as [&str; 0], "not even the directory");
    assert_eq!(disk.calls(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_free_space_falling_mid_transfer_stops_the_file() {
    let dest = Tmp::new("midway");
    let size = 3 * CHECK_EVERY;
    let room = Space { avail: 100 * MIB };
    let full = Space { avail: 0 };
    // Batch check, file check, first mid-transfer check pass; then the disk is full.
    let disk = Scripted::new(&[room, room, room, full]);
    let mut setup = Setup::new(Arc::clone(&disk) as SpaceProbe);
    setup.opts.free_space_reserve_bytes = MIB;
    let server = Hostile::file("/f", Some(size), size);
    let message = failure(run(server, setup, &dest.0).await);
    assert_eq!(
        message,
        "local free space fell below the reserve (1048576 bytes); download stopped"
    );
    assert_eq!(disk.calls(), 4);
    assert_eq!(
        dest.names(),
        [] as [&str; 0],
        "the .part it created is removed"
    );
}
