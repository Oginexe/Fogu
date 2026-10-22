#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use fogu_session::sftp::{CmdId, Failed, Skipped};

use super::*;

fn dl_origin() -> Origin {
    Origin::Download {
        remote_dir: "/srv/data".into(),
        local_dir: PathBuf::from("/tmp/dl"),
    }
}

#[test]
fn transfer_list_lifecycle() {
    let t0 = Instant::now();
    let mut list = Transfers::default();
    list.push(Transfer::new(
        CmdId(1),
        Direction::Download,
        "a".into(),
        dl_origin(),
    ));
    list.push(Transfer::new(
        CmdId(2),
        Direction::Upload,
        "b".into(),
        dl_origin(),
    ));
    list.queued(CmdId(1), 3, 1000);
    list.progress(CmdId(1), 250, 1000, 50);
    let t = list.get(CmdId(1)).unwrap();
    assert_eq!(t.state, TransferState::Running);
    assert!((t.fraction() - 0.25).abs() < 1e-6);
    let report = TransferReport {
        files_done: 3,
        bytes: 1000,
        ..TransferReport::default()
    };
    assert!(
        list.finish(CmdId(1), TransferState::Done, &report, t0)
            .is_some()
    );
    // A second final event, or progress after the end, changes nothing.
    assert!(
        list.finish(CmdId(1), TransferState::Cancelled, &report, t0)
            .is_none()
    );
    list.progress(CmdId(1), 1, 1000, 1);
    assert_eq!(list.get(CmdId(1)).unwrap().state, TransferState::Done);
    assert!((list.get(CmdId(1)).unwrap().fraction() - 1.0).abs() < 1e-6);
    assert_eq!(list.active_count(), 1);
    let linger = Duration::from_secs(10);
    assert!(list.sweep(t0 + Duration::from_secs(9), linger, &Conflicts::default()));
    assert_eq!(list.items.len(), 2);
    // A transfer whose conflict still waits for an answer is kept (its origin is needed).
    let mut pinned = Conflicts::default();
    pinned.queue.push_back(Conflict {
        transfer: CmdId(1),
        path: "x".into(),
        kind: ConflictKind::Exists,
        resumable: false,
    });
    assert!(list.sweep(t0 + linger, linger, &pinned));
    list.clear_finished(&pinned);
    assert_eq!(list.items.len(), 2, "kept while its conflict is open");
    assert!(!list.sweep(t0 + linger, linger, &Conflicts::default()));
    assert_eq!(list.items.len(), 1, "finished one removed after linger");
    list.fail_active("connection closed", t0);
    assert_eq!(
        list.get(CmdId(2)).unwrap().state,
        TransferState::Failed("connection closed".into())
    );
    list.clear_finished(&Conflicts::default());
    assert_eq!(list.items.len(), 0);
}

#[test]
fn conflict_answers_one_or_all() {
    let c = |n: u64, p: &str| Conflict {
        transfer: CmdId(n),
        path: p.into(),
        kind: ConflictKind::Exists,
        resumable: false,
    };
    let mut q = Conflicts::default();
    q.queue.extend([c(1, "a"), c(1, "b"), c(2, "x")]);
    assert_eq!(q.current().unwrap().path, "a");
    assert_eq!(q.answer(ConflictChoice::Overwrite), vec![c(1, "a")]);
    assert_eq!(q.answer(ConflictChoice::Skip), vec![]);
    q.queue.push_back(c(3, "y"));
    q.apply_all = true;
    assert_eq!(
        q.answer(ConflictChoice::Overwrite),
        vec![c(2, "x"), c(3, "y")]
    );
    assert!(q.current().is_none());
    assert!(!q.apply_all, "reset once the queue is empty");
}

#[test]
fn resume_for_all_takes_only_resumable_conflicts() {
    let c = |p: &str, resumable| Conflict {
        transfer: CmdId(1),
        path: p.into(),
        kind: ConflictKind::PartialExists,
        resumable,
    };
    let mut q = Conflicts::default();
    q.queue
        .extend([c("a", true), c("b", false), c("c", true), c("d", false)]);
    q.apply_all = true;
    assert_eq!(
        q.answer(ConflictChoice::Resume),
        vec![c("a", true), c("c", true)]
    );
    // The others are asked next, one by one.
    assert_eq!(q.current().unwrap().path, "b");
    assert!(q.apply_all, "still more to answer");
    assert_eq!(
        q.answer(ConflictChoice::KeepBoth),
        vec![c("b", false), c("d", false)]
    );
    let as_cmd = |choice: ConflictChoice| choice.reissue_as();
    assert_eq!(
        as_cmd(ConflictChoice::Resume),
        Some((OverwritePolicy::Ask, true))
    );
    assert_eq!(
        as_cmd(ConflictChoice::KeepBoth),
        Some((OverwritePolicy::KeepBoth, false))
    );
    assert_eq!(as_cmd(ConflictChoice::Skip), None);
}

const OVERWRITE: (OverwritePolicy, bool) = (OverwritePolicy::Overwrite, false);

#[test]
fn reissue_downloads_group_by_local_dir_and_reject_bad_names() {
    let rels = [
        "dir/sub/f1".to_owned(),
        "dir/sub/f2".to_owned(),
        "top".to_owned(),
        "dir/../../etc/passwd".to_owned(),
        "a/\u{1b}x".to_owned(),
        "/abs".to_owned(),
    ];
    let (cmds, rejected) = reissue(&dl_origin(), &rels, OVERWRITE);
    assert_eq!(rejected.len(), 3, "{rejected:?}");
    assert!(rejected.iter().all(|r| !r.contains('\u{1b}')));
    assert_eq!(cmds.len(), 2);
    let SftpCmd::Download {
        remote,
        local_dir,
        overwrite,
        resume,
    } = &cmds[0]
    else {
        panic!("download expected");
    };
    assert_eq!(
        remote,
        &vec![
            "/srv/data/dir/sub/f1".to_owned(),
            "/srv/data/dir/sub/f2".to_owned()
        ]
    );
    assert_eq!(local_dir, &PathBuf::from("/tmp/dl/dir/sub"));
    assert_eq!(*overwrite, OverwritePolicy::Overwrite);
    assert!(!resume);
    let SftpCmd::Download {
        remote, local_dir, ..
    } = &cmds[1]
    else {
        panic!("download expected");
    };
    assert_eq!(remote, &vec!["/srv/data/top".to_owned()]);
    assert_eq!(local_dir, &PathBuf::from("/tmp/dl"));
}

#[test]
fn reissue_uploads_map_back_to_their_source() {
    let origin = Origin::Upload {
        local: vec![
            PathBuf::from("/home/me/pics"),
            PathBuf::from("/home/me/a.txt"),
        ],
        remote_dir: "/srv".into(),
    };
    let rels = [
        "pics/2026/x.jpg".to_owned(),
        "a.txt".to_owned(),
        "unknown.txt".to_owned(),
    ];
    let (cmds, rejected) = reissue(&origin, &rels, (OverwritePolicy::KeepBoth, false));
    assert_eq!(rejected, vec!["unknown.txt".to_owned()]);
    let got: Vec<(Vec<PathBuf>, String)> = cmds
        .into_iter()
        .map(|c| match c {
            SftpCmd::Upload {
                local,
                remote_dir,
                overwrite: OverwritePolicy::KeepBoth,
                resume: false,
            } => (local, remote_dir),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        got,
        vec![
            (
                vec![PathBuf::from("/home/me/pics/2026/x.jpg")],
                "/srv/pics/2026".to_owned()
            ),
            (vec![PathBuf::from("/home/me/a.txt")], "/srv".to_owned()),
        ]
    );
}

#[cfg(unix)]
#[test]
fn real_subdir_refuses_symlinked_components() {
    let base = std::env::temp_dir().join(format!("fogu-ui-subdir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("real/inner")).unwrap();
    std::os::unix::fs::symlink("/tmp", base.join("link")).unwrap();
    assert!(real_subdir(&base, &base));
    assert!(real_subdir(&base, &base.join("real/inner")));
    assert!(!real_subdir(&base, &base.join("link")));
    assert!(!real_subdir(&base, &base.join("missing")));
    assert!(!real_subdir(&base, Path::new("/etc")));
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn summary_and_conflict_texts_are_sanitized() {
    let report = TransferReport {
        files_done: 2,
        skipped: vec![
            Skipped {
                path: "x".into(),
                reason: SkipReason::Exists(ConflictKind::Exists),
            },
            Skipped {
                path: "loop".into(),
                reason: SkipReason::SymlinkToDir,
            },
        ],
        failed: vec![Failed {
            path: "bad\u{1b}name".into(),
            message: "permission denied".into(),
        }],
        ..TransferReport::default()
    };
    assert_eq!(
        report_summary(&report),
        "2 file(s), 1 already existed, 1 skipped, 1 failed (bad\\x1bname: permission denied)"
    );
    let c = Conflict {
        transfer: CmdId(1),
        path: "evil\u{202e}gpj.exe".into(),
        kind: ConflictKind::Exists,
        resumable: false,
    };
    let text = conflict_text(&c, Direction::Download);
    assert!(text.contains("\\u{202e}"), "{text}");
}
