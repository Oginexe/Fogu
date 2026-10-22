//! Reducer tests: `SftpPanelState` against a plain command channel, and the panel inside a
//! headless `App` with an SSH stub session.
#![expect(clippy::unwrap_used, clippy::panic, reason = "tests")]

use std::sync::Arc;
use std::time::Instant;

use fogu_core::{Action, Config, Profile, ProfileId, ProfileKind, SshOpts};
use fogu_session::sftp::{ConflictKind, Entry, EntryKind, SftpOptions, TransferReport};
use fogu_session::{SessionRuntime, SftpCmd, SftpEvent, SftpRequest};
use tokio::sync::mpsc::{self, Receiver, Sender};

use super::transfers::{ConflictChoice, Direction, Origin, TransferState};
use super::*;
use crate::app::App;
use crate::message::Message;
use crate::metrics::{FontUnits, ResolvedFont};

pub(super) fn channel() -> (Sender<SftpRequest>, Receiver<SftpRequest>) {
    mpsc::channel(64)
}

pub(super) fn drain(rx: &mut Receiver<SftpRequest>) -> Vec<SftpRequest> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

pub(super) fn file(name: &str) -> Entry {
    Entry {
        name: name.to_owned(),
        kind: EntryKind::File,
        size: Some(10),
        mtime: Some(0),
        mode: Some(0o644),
        uid: None,
        gid: None,
        link_target: None,
        link_kind: None,
    }
}

pub(super) fn listing(id: CmdId, path: &str, names: &[&str]) -> SftpEvent {
    SftpEvent::Listing {
        id,
        path: path.to_owned(),
        entries: names.iter().map(|n| file(n)).collect(),
        truncated: false,
    }
}

/// A visible panel showing `/home/u` (login directory) with entries `a`, `b`.
pub(super) fn at_home(tx: &Sender<SftpRequest>, rx: &mut Receiver<SftpRequest>) -> SftpPanelState {
    let mut panel = SftpPanelState::new(PaneId(1), &SftpCfg::default());
    panel.open(tx, SftpOptions::default(), None).unwrap();
    let sent = drain(rx);
    assert!(matches!(sent[0].cmd, SftpCmd::SetOptions(_)));
    let SftpCmd::Realpath(ref dot) = sent[1].cmd else {
        panic!("realpath first");
    };
    assert_eq!(dot, ".");
    let now = Instant::now();
    let r = panel.on_event(
        SftpEvent::Realpath {
            id: sent[1].id,
            path: "/home/u".into(),
        },
        tx,
        now,
    );
    assert_eq!(r.notes.len(), 0);
    let sent = drain(rx);
    let SftpCmd::List(ref path) = sent[0].cmd else {
        panic!("list after realpath");
    };
    assert_eq!(path, "/home/u");
    assert!(panel.loading.is_some());
    panel.on_event(listing(sent[0].id, "/home/u", &["a", "b"]), tx, now);
    assert_eq!(panel.path.as_deref(), Some("/home/u"));
    assert_eq!(panel.home.as_deref(), Some("/home/u"));
    assert!(panel.loading.is_none());
    assert_eq!(panel.back.len(), 0);
    panel
}

#[test]
fn first_open_resolves_home_then_lists_it() {
    let (tx, mut rx) = channel();
    let panel = at_home(&tx, &mut rx);
    assert!(panel.visible && panel.focused);
    assert_eq!(panel.listing.entries.len(), 2);
    let crumbs: Vec<String> = breadcrumb::segments(panel.path.as_deref().unwrap())
        .into_iter()
        .map(|s| s.path)
        .collect();
    assert_eq!(crumbs, ["/", "/home", "/home/u"]);
}

#[test]
fn profile_cwd_is_the_start_directory() {
    let (tx, mut rx) = channel();
    let mut panel = SftpPanelState::new(PaneId(1), &SftpCfg::default());
    panel
        .open(&tx, SftpOptions::default(), Some("/srv/www".into()))
        .unwrap();
    let sent = drain(&mut rx);
    assert!(matches!(&sent[1].cmd, SftpCmd::Realpath(p) if p == "/srv/www"));
    panel.on_event(
        SftpEvent::Realpath {
            id: sent[1].id,
            path: "/srv/www".into(),
        },
        &tx,
        Instant::now(),
    );
    assert!(panel.home.is_none(), "not the login directory");
}

#[test]
fn navigation_back_up_and_stale_or_failed_listings() {
    let (tx, mut rx) = channel();
    let mut panel = at_home(&tx, &mut rx);
    let now = Instant::now();
    panel.list(&tx, "/home/u/docs".into(), true).unwrap();
    let docs = drain(&mut rx)[0].id;
    // A newer navigation wins over the older one still in flight.
    panel.list(&tx, "/tmp".into(), true).unwrap();
    let tmp = drain(&mut rx)[0].id;
    panel.on_event(listing(docs, "/home/u/docs", &["x"]), &tx, now);
    assert_eq!(
        panel.path.as_deref(),
        Some("/home/u"),
        "stale answer ignored"
    );
    panel.on_event(listing(tmp, "/tmp", &["t"]), &tx, now);
    assert_eq!(panel.path.as_deref(), Some("/tmp"));
    assert_eq!(panel.back, ["/home/u"]);
    // A failing listing keeps the previous one and reports it.
    panel.go_up(&tx).unwrap();
    let up = drain(&mut rx);
    assert!(matches!(&up[0].cmd, SftpCmd::List(p) if p == "/"));
    let r = panel.on_event(
        SftpEvent::Error {
            id: up[0].id,
            message: "permission denied".into(),
        },
        &tx,
        now,
    );
    assert_eq!(r.notes.len(), 1);
    assert_eq!(r.notes[0].title, "Cannot open /");
    assert_eq!(panel.path.as_deref(), Some("/tmp"));
    assert!(panel.loading.is_none() && panel.error.is_none());
    assert_eq!(panel.listing.entries[0].name, "t");
    // Back does not push again.
    panel.go_back(&tx).unwrap();
    let back = drain(&mut rx);
    assert!(matches!(&back[0].cmd, SftpCmd::List(p) if p == "/home/u"));
    panel.on_event(listing(back[0].id, "/home/u", &["a"]), &tx, now);
    assert_eq!(panel.back.len(), 0);
}

#[test]
fn failing_first_listing_shows_the_error_in_the_panel() {
    let (tx, mut rx) = channel();
    let mut panel = SftpPanelState::new(PaneId(1), &SftpCfg::default());
    panel.open(&tx, SftpOptions::default(), None).unwrap();
    let id = drain(&mut rx)[1].id;
    panel.on_event(
        SftpEvent::Error {
            id,
            message: "no such file".into(),
        },
        &tx,
        Instant::now(),
    );
    assert!(panel.error.as_deref().unwrap().contains("no such file"));
}

#[test]
fn transfer_events_drive_the_list_and_toasts() {
    let (tx, mut rx) = channel();
    let mut panel = at_home(&tx, &mut rx);
    let now = Instant::now();
    let origin = Origin::Download {
        remote_dir: "/home/u".into(),
        local_dir: "/tmp".into(),
    };
    let cmd = download_cmd(vec!["/home/u/a".into()], "/tmp".into());
    assert_eq!(transfer_label(&cmd), "a");
    panel
        .issue(&tx, cmd, Direction::Download, "a".into(), origin)
        .unwrap();
    let id = drain(&mut rx)[0].id;
    panel.on_event(
        SftpEvent::TransferQueued {
            id,
            files: 1,
            total: 10,
        },
        &tx,
        now,
    );
    panel.on_event(
        SftpEvent::TransferProgress {
            id,
            bytes: 5,
            total: 10,
            rate: 100,
        },
        &tx,
        now,
    );
    assert_eq!(
        panel.transfers.get(id).unwrap().state,
        TransferState::Running
    );
    let r = panel.on_event(
        SftpEvent::TransferDone {
            id,
            report: TransferReport {
                files_done: 1,
                bytes: 10,
                ..TransferReport::default()
            },
        },
        &tx,
        now,
    );
    assert!(r.sweep);
    assert_eq!(r.notes[0].title, "Download finished");
    assert_eq!(panel.transfers.get(id).unwrap().state, TransferState::Done);
}

#[test]
fn finished_upload_into_the_shown_directory_refreshes_it() {
    let (tx, mut rx) = channel();
    let mut panel = at_home(&tx, &mut rx);
    let origin = Origin::Upload {
        local: vec!["/tmp/new.txt".into()],
        remote_dir: "/home/u".into(),
    };
    let cmd = SftpCmd::Upload {
        local: vec!["/tmp/new.txt".into()],
        remote_dir: "/home/u".into(),
        overwrite: OverwritePolicy::Ask,
        resume: false,
    };
    panel
        .issue(&tx, cmd, Direction::Upload, "new.txt".into(), origin)
        .unwrap();
    let id = drain(&mut rx)[0].id;
    let report = TransferReport::default();
    panel.on_event(SftpEvent::TransferDone { id, report }, &tx, Instant::now());
    let sent = drain(&mut rx);
    assert!(matches!(&sent[0].cmd, SftpCmd::List(p) if p == "/home/u"));
}

#[test]
fn conflict_overwrite_reissues_only_that_file() {
    let (tx, mut rx) = channel();
    let mut panel = at_home(&tx, &mut rx);
    let local = std::env::temp_dir();
    let origin = Origin::Download {
        remote_dir: "/home/u".into(),
        local_dir: local.clone(),
    };
    let cmd = download_cmd(vec!["/home/u/a".into(), "/home/u/b".into()], local.clone());
    panel
        .issue(&tx, cmd, Direction::Download, "a + 1 more".into(), origin)
        .unwrap();
    let id = drain(&mut rx)[0].id;
    let now = Instant::now();
    for name in ["a", "b"] {
        panel.on_event(
            SftpEvent::Conflict {
                id,
                path: name.into(),
                kind: ConflictKind::Exists,
                resumable: false,
            },
            &tx,
            now,
        );
    }
    // Conflicts of an unknown transfer are ignored.
    panel.on_event(
        SftpEvent::Conflict {
            id: CmdId(999),
            path: "zzz".into(),
            kind: ConflictKind::Exists,
            resumable: false,
        },
        &tx,
        now,
    );
    assert_eq!(panel.conflicts.queue.len(), 2);
    assert!(
        panel
            .answer_conflict(&tx, ConflictChoice::Overwrite)
            .is_empty()
    );
    let sent = drain(&mut rx);
    assert_eq!(sent.len(), 1);
    let SftpCmd::Download {
        remote,
        local_dir,
        overwrite,
        ..
    } = &sent[0].cmd
    else {
        panic!("download expected");
    };
    assert_eq!(remote, &vec!["/home/u/a".to_owned()]);
    assert_eq!(local_dir, &local);
    assert_eq!(*overwrite, OverwritePolicy::Overwrite);
    assert_eq!(panel.transfers.items.len(), 2, "a new row for the re-issue");
    assert_eq!(panel.answer_conflict(&tx, ConflictChoice::Skip).len(), 0);
    assert_eq!(drain(&mut rx).len(), 0, "skip sends nothing");
    assert!(panel.conflicts.current().is_none());
}

#[test]
fn closed_channel_fails_running_transfers_and_rebind_resets() {
    let (tx, mut rx) = channel();
    let mut panel = at_home(&tx, &mut rx);
    let origin = Origin::Download {
        remote_dir: "/home/u".into(),
        local_dir: "/tmp".into(),
    };
    let cmd = download_cmd(vec!["/home/u/a".into()], "/tmp".into());
    panel
        .issue(&tx, cmd, Direction::Download, "a".into(), origin)
        .unwrap();
    let id = drain(&mut rx)[0].id;
    let r = panel.on_event(SftpEvent::Closed, &tx, Instant::now());
    assert!(r.sweep);
    assert_eq!(
        panel.transfers.get(id).unwrap().state,
        TransferState::Failed("connection closed".into())
    );
    panel.list(&tx, "/x".into(), true).unwrap();
    panel.rebind(PaneId(7), Instant::now());
    assert_eq!(panel.pane, PaneId(7));
    assert!(panel.loading.is_none());
    // A closed engine channel is reported, not a panic.
    drop(rx);
    assert_eq!(
        panel.list(&tx, "/".into(), false),
        Err("the connection is closed".into())
    );
}

#[test]
fn config_defaults_match_the_engine_defaults() {
    assert_eq!(engine_options(&SftpCfg::default()), SftpOptions::default());
    let cfg = SftpCfg {
        max_parallel_files: 0,
        max_download_bytes: Some(5),
        ..SftpCfg::default()
    };
    let opts = engine_options(&cfg);
    assert_eq!(opts.max_parallel_files, 1);
    assert_eq!(opts.max_download_bytes, Some(5));
}

pub(super) fn ssh_app() -> App {
    let runtime = Arc::new(SessionRuntime::new().unwrap());
    let resolved = ResolvedFont {
        font: iced::Font::MONOSPACE,
        units: FontUnits::FALLBACK,
    };
    let mut app = App::new(runtime, Arc::new(Config::default()), resolved);
    let profile = Profile {
        id: ProfileId("box".to_owned()),
        name: "Box".to_owned(),
        kind: ProfileKind::Ssh(SshOpts {
            host: Some("box.lan".to_owned()),
            user: Some("alice".to_owned()),
            ..SshOpts::default()
        }),
        ..Profile::default_shell()
    };
    app.open_tab(&profile, None);
    app
}

#[test]
fn toggle_opens_and_hides_the_panel_on_an_ssh_tab_only() {
    let mut app = ssh_app();
    let _ = app.update(Message::Action(Action::ToggleSftp));
    let tab = app.active_tab().unwrap();
    let panel = tab.sftp.as_ref().unwrap();
    assert!(panel.visible);
    assert_eq!(panel.pane, tab.focused);
    let sent = drain(&mut app.stub_sftp[0]);
    assert!(matches!(sent[0].cmd, SftpCmd::SetOptions(_)));
    assert!(matches!(&sent[1].cmd, SftpCmd::Realpath(p) if p == "."));
    // Keys go to the panel after a click inside it; a click elsewhere gives them back.
    let tab_id = app.active;
    let _ = app.update(Message::Sftp(SftpMsg::Panel(tab_id, PanelMsg::Hover(true))));
    let _ = app.update(Message::MousePressed);
    assert!(app.panel_has_keys());
    let _ = app.update(Message::Sftp(SftpMsg::Panel(
        tab_id,
        PanelMsg::Hover(false),
    )));
    let _ = app.update(Message::MousePressed);
    assert!(!app.panel_has_keys());
    // Engine events reach the panel by pane id.
    let pane = app.active_tab().unwrap().focused;
    let realpath = SftpEvent::Realpath {
        id: sent[1].id,
        path: "/home/alice".into(),
    };
    let _ = app.update(Message::Sftp(SftpMsg::Event(pane, Box::new(realpath))));
    let sent = drain(&mut app.stub_sftp[0]);
    assert!(matches!(&sent[0].cmd, SftpCmd::List(p) if p == "/home/alice"));
    // Hide: the engine is told to close its channel, the shell is untouched.
    let _ = app.update(Message::Action(Action::ToggleSftp));
    assert!(!app.active_tab().unwrap().sftp.as_ref().unwrap().visible);
    let sent = drain(&mut app.stub_sftp[0]);
    assert!(matches!(sent[0].cmd, SftpCmd::Shutdown));
    assert!(
        app.stub_inputs[0].try_recv().is_err(),
        "nothing sent to the shell"
    );

    // A local tab has no panel, only a hint.
    let local = app.default_profile();
    app.open_tab(&local, None);
    let _ = app.update(Message::Action(Action::ToggleSftp));
    assert!(app.active_tab().unwrap().sftp.is_none());
    assert!(app.toasts.iter().any(|t| t.title == "SFTP"));
}

#[test]
fn reconnect_rebinds_the_panel_to_the_new_pane() {
    let mut app = ssh_app();
    let _ = app.update(Message::Action(Action::ToggleSftp));
    let old = app.active_tab().unwrap().focused;
    let _ = app.update(Message::Action(Action::Reconnect));
    let tab = app.active_tab().unwrap();
    assert_ne!(tab.focused, old);
    assert_eq!(tab.sftp.as_ref().unwrap().pane, tab.focused);
    // The new connection's engine got the options and the start directory again.
    let sent = drain(&mut app.stub_sftp[1]);
    assert!(matches!(sent[0].cmd, SftpCmd::SetOptions(_)));
    assert!(matches!(&sent[1].cmd, SftpCmd::Realpath(_)));
}

#[test]
fn navigating_elsewhere_leaves_the_path_field() {
    let (tx, mut rx) = channel();
    let mut panel = at_home(&tx, &mut rx);
    panel.editing = Some("/home/u".into());
    panel.list(&tx, "/home/u/docs".into(), true).unwrap();
    let docs = drain(&mut rx)[0].id;
    panel.on_event(listing(docs, "/home/u/docs", &["x"]), &tx, Instant::now());
    assert_eq!(panel.editing, None, "the bar shows the new directory");
}
