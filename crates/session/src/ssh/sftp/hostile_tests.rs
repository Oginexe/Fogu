//! Malicious-server tests: the engine against `hostile_server.rs` sending hostile names, a symlink
//! loop, a lying `realpath`, an endless listing, oversized data replies, absurd sizes, a tree over
//! the caps and a server on which every name "exists". Asserted: writes land only below the
//! destination, bad names are skipped and reported, nothing is deleted on a refused tree, no panic
//! anywhere.
#![expect(clippy::unwrap_used, clippy::panic, reason = "tests")]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::Semaphore;
use tokio::sync::mpsc::{self, Receiver};
use tokio_util::sync::CancellationToken;

use super::download::download;
use super::download::tests::{Tmp, fatal, report};
use super::hostile_server::{ENDLESS, Hostile, Node, content, plenty};
use super::ops;
use super::remote::Remote;
use super::transfer::Ctx;
use super::upload::upload;
use crate::sftp::{
    CmdId, Entry, NameError, OverwritePolicy, SftpCmd, SftpEvent, SftpOptions, SkipReason,
    TransferReport, display_name, validate_name,
};

/// The hostile names under test: `..`, `a/b`, `.`, empty, an OSC 52 injection, `-rf`, a
/// 4096-byte name, plus one honest file and a symlink loop `l -> .`.
const INJECTION: &str = "evil\x1b]52;c;AAAA\x07";

fn long_name() -> String {
    "n".repeat(4096)
}

/// `/d` with every hostile entry; the honest ones are `ok` (3 bytes) and `-rf` (2 bytes).
fn hostile_dir() -> Hostile {
    let names = vec![
        "..".to_owned(),
        "a/b".to_owned(),
        ".".to_owned(),
        String::new(),
        INJECTION.to_owned(),
        "-rf".to_owned(),
        long_name(),
        "l".to_owned(),
        "ok".to_owned(),
    ];
    let file = |n| Node::File {
        reported: Some(n),
        actual: n,
    };
    Hostile::default()
        .with("/d", Node::Dir(names))
        .with("/d/ok", file(3))
        .with("/d/-rf", file(2))
        .with(&format!("/d/{INJECTION}"), file(5))
        .with(&format!("/d/{}", long_name()), file(7))
        .with(
            "/d/l",
            Node::Symlink {
                target: ".".into(),
                resolves_to: Some("/d".into()),
            },
        )
        .realpath_of("/d", "/etc/../../tmp")
}

/// A connected engine context plus the event receiver.
async fn connect(server: Hostile, opts: SftpOptions) -> (Ctx, Receiver<SftpEvent>) {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    russh_sftp::server::run(server_io, server).await;
    let remote = Remote::over(client_io, &opts).await.unwrap();
    let (events, rx) = mpsc::channel(4096);
    let ctx = Ctx {
        id: CmdId(1),
        remote: Arc::new(remote),
        events,
        cancel: CancellationToken::new(),
        slots: Arc::new(Semaphore::new(4)),
        opts,
        space: plenty(),
    };
    (ctx, rx)
}

/// Runs one metadata command and returns its single answer.
async fn op(ctx: &Ctx, cmd: SftpCmd) -> SftpEvent {
    let (events, mut rx) = mpsc::channel(16);
    ops::run(
        Arc::clone(&ctx.remote),
        ctx.opts.clone(),
        CmdId(7),
        cmd,
        events,
    )
    .await;
    rx.recv().await.unwrap()
}

/// Downloads `roots` into `dest`; returns the final event.
async fn fetch(ctx: Ctx, mut rx: Receiver<SftpEvent>, roots: &[&str], dest: &Path) -> SftpEvent {
    let roots = roots.iter().map(|r| (*r).to_owned()).collect();
    tokio::spawn(download(
        ctx,
        roots,
        dest.to_owned(),
        OverwritePolicy::Ask,
        false,
    ));
    final_event(&mut rx).await
}

async fn final_event(rx: &mut Receiver<SftpEvent>) -> SftpEvent {
    loop {
        match rx.recv().await.unwrap() {
            SftpEvent::TransferQueued { .. } | SftpEvent::TransferProgress { .. } => {}
            end => return end,
        }
    }
}

fn skipped<'a>(report: &'a TransferReport, path: &str) -> &'a SkipReason {
    &report
        .skipped
        .iter()
        .find(|s| s.path == path)
        .unwrap_or_else(|| panic!("{path:?} not skipped: {report:?}"))
        .reason
}

/// Every name under `dir`, recursively, relative to it and sorted.
fn tree(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &path, out);
            }
            out.push(path);
        }
    }
    let mut out = Vec::new();
    walk(dir, "", &mut out);
    out.sort();
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_hostile_listing_drops_unusable_names_and_displays_safely() {
    let (ctx, _rx) = connect(hostile_dir(), SftpOptions::default()).await;
    let SftpEvent::Listing {
        entries, truncated, ..
    } = op(&ctx, SftpCmd::List("/d".into())).await
    else {
        panic!("no listing")
    };
    assert!(!truncated);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    // `..`, `a/b`, `.` and the empty name never reach the UI; the rest is listed raw, the
    // link to a directory first.
    let long = long_name();
    assert_eq!(names, ["l", "-rf", INJECTION, &long, "ok"]);
    for entry in &entries {
        let shown = display_name(&entry.name);
        assert!(!shown.chars().any(char::is_control), "{shown:?}");
        assert!(shown.chars().count() <= 256, "{}", shown.len());
    }
    let link: &Entry = entries.iter().find(|e| e.name == "l").unwrap();
    assert_eq!(link.link_target.as_deref(), Some("."));
    assert_eq!(link.link_kind, Some(crate::sftp::EntryKind::Dir));
    // The names the listing dropped would be refused as local components anyway.
    assert_eq!(validate_name(".."), Err(NameError::Dot));
    assert_eq!(validate_name("a/b"), Err(NameError::Slash));
    assert_eq!(validate_name(""), Err(NameError::Empty));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_hostile_realpath_is_passed_through_raw() {
    let (ctx, _rx) = connect(hostile_dir(), SftpOptions::default()).await;
    // A lying realpath only ever addresses the server again; it never becomes a local path.
    match op(&ctx, SftpCmd::Realpath("/d".into())).await {
        SftpEvent::Realpath { path, .. } => assert_eq!(path, "/etc/../../tmp"),
        other => panic!("{other:?}"),
    }
    assert_eq!(ops::last_component("/etc/../../tmp"), "tmp");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_hostile_recursive_download_stays_inside_the_destination() {
    let dest = Tmp::new("hostile-tree");
    let (ctx, rx) = connect(hostile_dir(), SftpOptions::default()).await;
    let end = fetch(ctx, rx, &["/d"], &dest.0).await;
    let done = report(end);
    assert_eq!((done.files_done, done.dirs_created, done.bytes), (2, 1, 5));
    assert_eq!(tree(&dest.0), ["d", "d/-rf", "d/ok"]);
    assert_eq!(std::fs::read(dest.0.join("d/ok")).unwrap(), content(3));
    assert_eq!(
        *skipped(&done, &format!("d/{INJECTION}")),
        SkipReason::InvalidName(NameError::Control)
    );
    assert_eq!(
        *skipped(&done, &format!("d/{}", long_name())),
        SkipReason::InvalidName(NameError::Invalid)
    );
    assert_eq!(*skipped(&done, "d/l"), SkipReason::SymlinkToDir);
    assert_eq!(done.skipped.len(), 3, "{:?}", done.skipped);
    assert!(done.failed.is_empty(), "{:?}", done.failed);
    // Roots with hostile names are refused before anything is looked up.
    let dest2 = Tmp::new("hostile-roots");
    let (ctx, rx) = connect(hostile_dir(), SftpOptions::default()).await;
    let done = report(fetch(ctx, rx, &["/d/..", "/d/a/b", "/"], &dest2.0).await);
    assert_eq!(done.files_done, 0);
    assert_eq!(dest2.names(), [] as [&str; 0]);
    assert_eq!(done.skipped.len() + done.failed.len(), 3, "{done:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_hostile_endless_listing_is_cut_and_refused_for_a_walk() {
    let opts = SftpOptions {
        max_listing_entries: 250,
        ..SftpOptions::default()
    };
    let server = Hostile::default().endless_dir("/forever");
    let (ctx, rx) = connect(server, opts).await;
    match op(&ctx, SftpCmd::List("/forever".into())).await {
        SftpEvent::Listing {
            entries, truncated, ..
        } => {
            assert!(truncated);
            assert_eq!(entries.len(), 250);
        }
        other => panic!("{other:?}"),
    }
    let dest = Tmp::new("hostile-endless");
    let message = fatal(fetch(ctx, rx, &["/forever"], &dest.0).await);
    assert!(message.contains("too large"), "{message}");
    assert_eq!(dest.names(), [] as [&str; 0], "not even the directory");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_hostile_oversized_data_reply_fails_the_file() {
    let dest = Tmp::new("hostile-oversize");
    let server = Hostile::file("/f", Some(100_000), ENDLESS).oversize_reads();
    let (ctx, rx) = connect(server, SftpOptions::default()).await;
    let done = report(fetch(ctx, rx, &["/f"], &dest.0).await);
    assert_eq!(done.files_done, 0);
    assert_eq!(
        done.failed[0].message,
        "the server sent more data than requested"
    );
    assert_eq!(dest.names(), [] as [&str; 0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_hostile_absurd_sizes_do_not_overflow() {
    let dest = Tmp::new("hostile-sizes");
    let huge = Node::File {
        reported: Some(u64::MAX),
        actual: 10,
    };
    let server = Hostile::default()
        .with("/d", Node::Dir(vec!["a".into(), "b".into()]))
        .with("/d/a", huge.clone())
        .with("/d/b", huge);
    // Each file is planned at the limit, so the batch fits; the summed total must saturate.
    let opts = SftpOptions {
        max_download_bytes: Some(1 << 20),
        ..SftpOptions::default()
    };
    let (ctx, mut rx) = connect(server, opts).await;
    tokio::spawn(download(
        ctx,
        vec!["/d".into()],
        dest.0.clone(),
        OverwritePolicy::Ask,
        false,
    ));
    let mut total = None;
    let end = loop {
        match rx.recv().await.unwrap() {
            SftpEvent::TransferQueued { total: t, .. } => total = Some(t),
            SftpEvent::TransferProgress { .. } => {}
            end => break end,
        }
    };
    assert_eq!(total, Some(u64::MAX));
    let done = report(end);
    assert_eq!(done.failed.len(), 2, "{done:?}");
    assert!(
        done.failed[0]
            .message
            .contains("larger than the download limit")
    );
    assert_eq!(tree(&dest.0), ["d"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_hostile_count_and_delete_refuse_trees_over_the_caps_without_deleting() {
    let wide: Vec<String> = (0..300).map(|i| format!("f{i}")).collect();
    let mut server = Hostile::default().with("/wide", Node::Dir(wide));
    let mut path = "/deep".to_owned();
    for _ in 0..70 {
        server = server.with(&path, Node::Dir(vec!["s".into()]));
        path.push_str("/s");
    }
    server = server.with(&path, Node::Dir(Vec::new()));
    let removals = server.removals();
    let opts = SftpOptions {
        max_walk_entries: 100,
        ..SftpOptions::default()
    };
    let (ctx, _rx) = connect(server, opts).await;
    for (dir, why) in [("/wide", "max_walk_entries"), ("/deep", "max_walk_depth")] {
        match op(&ctx, SftpCmd::CountDir(dir.into())).await {
            SftpEvent::Error { message, .. } => assert!(message.contains(why), "{message}"),
            other => panic!("{other:?}"),
        }
        match op(&ctx, SftpCmd::RemoveDirRecursive(dir.into())).await {
            SftpEvent::Error { message, .. } => {
                assert!(message.contains(why) && message.ends_with("nothing was deleted"));
            }
            other => panic!("{other:?}"),
        }
    }
    // A symlink root is refused too (deleted as a link by the UI instead).
    let (ctx, _rx) = connect(hostile_dir(), SftpOptions::default()).await;
    assert!(matches!(
        op(&ctx, SftpCmd::RemoveDirRecursive("/d/l".into())).await,
        SftpEvent::Error { .. }
    ));
    assert_eq!(removals.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sftp_hostile_keep_both_gives_up_when_every_name_exists() {
    let src = Tmp::new("hostile-keepboth");
    std::fs::write(src.0.join("report.pdf"), b"x").unwrap();
    let server = Hostile::default()
        .with("/up", Node::Dir(Vec::new()))
        .everything_exists();
    let (ctx, mut rx) = connect(server, SftpOptions::default()).await;
    tokio::spawn(upload(
        ctx,
        vec![src.0.join("report.pdf")],
        "/up".into(),
        (OverwritePolicy::KeepBoth, false),
    ));
    let done = report(final_event(&mut rx).await);
    assert_eq!(done.files_done, 0);
    assert_eq!(done.failed[0].message, "no free name to keep both files");
}
