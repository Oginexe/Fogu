use std::path::PathBuf;
use std::sync::Arc;

use fogu_core::recovery::{self, SCROLLBACK_DIR};
use fogu_core::{Config, Profile, ProfileId, ProfileKind, RgbColor, Side, SshOpts};
use fogu_session::SessionRuntime;

use super::{InstanceClaim, Recovery};
use crate::RunOptions;
use crate::app::App;
use crate::metrics::{FontUnits, ResolvedFont};

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fogu-ui-recovery-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn app(config: Config) -> App {
    let runtime = Arc::new(SessionRuntime::new().unwrap());
    let resolved = ResolvedFont {
        font: iced::Font::MONOSPACE,
        units: FontUnits::FALLBACK,
    };
    App::new(runtime, Arc::new(config), resolved)
}

/// Two tabs: the first split in two, renamed and coloured, with output in its first pane.
fn two_tabs(app: &mut App) {
    let profile = app.default_profile();
    app.open_tab(&profile, None);
    let first = app.active_pane().unwrap().id;
    app.active_pane_mut()
        .unwrap()
        .term
        .feed(b"\x1b[32mhello from before\x1b[0m\r\nline two\r\n");
    app.split_now(first, Side::Right, None, None);
    let tab = app.tabs.iter_mut().find(|t| t.id == app.active).unwrap();
    tab.title_override = Some("logs".to_owned());
    tab.color = Some(RgbColor::from_hex(0x00e5_484d));
    app.open_tab(&profile, None);
}

fn save_now(app: &mut App, dir: &std::path::Path) {
    let mut rec = Recovery::new(dir.to_path_buf());
    app.save_recovery(&mut rec, true, true);
    app.recovery = Some(rec);
}

fn restore(app: &mut App, dir: &std::path::Path, enabled: bool) -> bool {
    let mut recovery = Recovery::new(dir.to_path_buf());
    app.restore_session(&mut recovery, enabled)
}

fn ssh_profile() -> Profile {
    Profile {
        id: ProfileId("ssh:box".to_owned()),
        name: "Box".to_owned(),
        kind: ProfileKind::Ssh(SshOpts {
            host: Some("box.example".to_owned()),
            user: Some("alice".to_owned()),
            ..SshOpts::default()
        }),
        ..Profile::default_shell()
    }
}

#[test]
fn a_restart_rebuilds_tabs_splits_titles_and_scrollback() {
    let dir = tmp("restart");
    let mut before = app(Config::default());
    two_tabs(&mut before);
    save_now(&mut before, &dir);
    assert_eq!(
        std::fs::read_dir(dir.join(SCROLLBACK_DIR)).unwrap().count(),
        3
    );

    let mut after = app(Config::default());
    assert!(restore(&mut after, &dir, true));
    assert_eq!(after.tabs.len(), 2);
    let tab = &after.tabs[0];
    assert_eq!(tab.layout.leaves().len(), 2);
    assert_eq!(tab.title_override.as_deref(), Some("logs"));
    assert_eq!(tab.color, Some(RgbColor::from_hex(0x00e5_484d)));
    assert_eq!(after.active, after.tabs[1].id, "the active tab too");
    let first = tab.panes[tab.layout.leaves()[0]].term.dump_grid();
    assert!(first.contains("hello from before"), "{first}");
    assert!(first.contains("restored from"), "{first}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_corrupt_scrollback_file_keeps_the_tab_and_says_so() {
    let dir = tmp("corrupt");
    let mut before = app(Config::default());
    two_tabs(&mut before);
    save_now(&mut before, &dir);
    for entry in std::fs::read_dir(dir.join(SCROLLBACK_DIR)).unwrap() {
        std::fs::write(entry.unwrap().path(), "{ not json").unwrap();
    }
    let mut after = app(Config::default());
    assert!(restore(&mut after, &dir, true));
    assert_eq!(after.tabs.len(), 2);
    assert!(!after.toasts.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn opted_out_profiles_write_no_scrollback_and_disabling_clears() {
    let dir = tmp("optout");
    let mut config = Config::default();
    config.recovery.restore_scrollback = false;
    let mut before = app(config);
    two_tabs(&mut before);
    save_now(&mut before, &dir);
    assert!(dir.join(recovery::SESSION_FILE).exists());
    let files = std::fs::read_dir(dir.join(SCROLLBACK_DIR)).map_or(0, Iterator::count);
    assert_eq!(files, 0);
    // A profile can still opt in.
    let mut config = Config::default();
    config.recovery.restore_scrollback = false;
    let mut mine = Profile::default_shell();
    mine.restore_scrollback = Some(true);
    let mut app2 = app(config);
    app2.open_tab(&mine, None);
    save_now(&mut app2, &dir);
    assert_eq!(
        std::fs::read_dir(dir.join(SCROLLBACK_DIR)).unwrap().count(),
        1
    );
    // `recovery.enabled = false` deletes everything at startup.
    let mut off = app(Config::default());
    assert!(!restore(&mut off, &dir, false));
    assert!(!dir.join(recovery::SESSION_FILE).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ssh_scrollback_is_never_written_without_the_setting_and_a_key() {
    for (name, enabled) in [("ssh-off", false), ("ssh-no-key", true)] {
        let dir = tmp(name);
        let mut config = Config::default();
        config.recovery.restore_ssh_scrollback = enabled;
        let mut before = app(config);
        before.open_tab(&ssh_profile(), None);
        before
            .active_pane_mut()
            .unwrap()
            .term
            .feed(b"password-looking output\r\n");
        save_now(&mut before, &dir);
        assert!(dir.join(recovery::SESSION_FILE).exists());
        let files = std::fs::read_dir(dir.join(SCROLLBACK_DIR)).map_or(0, Iterator::count);
        assert_eq!(files, 0, "{name}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(feature = "ssh")]
#[test]
fn ssh_scrollback_is_written_only_as_encrypted_data() {
    let dir = tmp("ssh-encrypted");
    let profile = ssh_profile();
    let mut config = Config::default();
    config.recovery.restore_ssh_scrollback = true;
    config.profiles.push(profile.clone());
    let mut before = app(config.clone());
    before.open_tab(&profile, None);
    before
        .active_pane_mut()
        .unwrap()
        .term
        .feed(b"private remote output\r\n");
    let mut recovery = Recovery::new(dir.clone());
    let key = fogu_session::new_recovery_key().unwrap();
    recovery.set_ssh_key(key.clone()).unwrap();
    before.save_recovery(&mut recovery, true, true);
    let paths: Vec<_> = std::fs::read_dir(dir.join(SCROLLBACK_DIR))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(paths.len(), 1);
    assert_eq!(
        paths[0].extension().and_then(|ext| ext.to_str()),
        Some("enc")
    );
    let mut after = app(config);
    let mut recovery = Recovery::new(dir.clone());
    recovery.set_ssh_key(key).unwrap();
    assert!(after.restore_session(&mut recovery, true));
    let grid = after.active_pane().unwrap().term.dump_grid();
    assert!(grid.contains("private remote output"), "{grid}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "ssh")]
#[test]
fn an_ssh_profile_can_opt_out_of_encrypted_scrollback() {
    let dir = tmp("ssh-profile-optout");
    let mut profile = ssh_profile();
    profile.restore_scrollback = Some(false);
    let mut config = Config::default();
    config.recovery.restore_ssh_scrollback = true;
    let mut before = app(config);
    before.open_tab(&profile, None);
    let mut recovery = Recovery::new(dir.clone());
    recovery
        .set_ssh_key(fogu_session::new_recovery_key().unwrap())
        .unwrap();
    before.save_recovery(&mut recovery, true, true);
    let files = std::fs::read_dir(dir.join(SCROLLBACK_DIR)).map_or(0, Iterator::count);
    assert_eq!(files, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "ssh")]
#[test]
fn locked_ssh_history_stays_linked_for_the_next_restart() {
    let dir = tmp("ssh-locked");
    let profile = ssh_profile();
    let mut config = Config::default();
    config.recovery.restore_ssh_scrollback = true;
    config.profiles.push(profile.clone());
    let mut before = app(config.clone());
    before.open_tab(&profile, None);
    before
        .active_pane_mut()
        .unwrap()
        .term
        .feed(b"old remote output\r\n");
    let mut written = Recovery::new(dir.clone());
    written
        .set_ssh_key(fogu_session::new_recovery_key().unwrap())
        .unwrap();
    before.save_recovery(&mut written, true, true);
    let old_key = recovery::load(&dir).unwrap().unwrap().tabs[0]
        .layout
        .leaves()[0]
        .key
        .clone();
    assert!(recovery::encrypted_scrollback_path(&dir, &old_key).exists());

    let mut after = app(config);
    let mut locked = Recovery::new(dir.clone());
    assert!(after.restore_session(&mut locked, true));
    let warnings: Vec<_> = after
        .toasts
        .iter()
        .filter(|note| note.title == "SSH history kept locked")
        .collect();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].detail, "The system keyring is not available.");
    after.save_recovery(&mut locked, true, true);
    let still_key = recovery::load(&dir).unwrap().unwrap().tabs[0]
        .layout
        .leaves()[0]
        .key
        .clone();
    assert_eq!(still_key, old_key);
    assert!(recovery::encrypted_scrollback_path(&dir, &old_key).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "ssh")]
#[test]
fn disabling_ssh_recovery_cancels_a_queued_encrypted_write() {
    let dir = tmp("ssh-disable-race");
    let mut recovery = Recovery::new(dir.clone());
    let secret = fogu_session::new_recovery_key().unwrap();
    recovery.set_ssh_key(secret.clone()).unwrap();
    recovery::save_encrypted_scrollback(&dir, "old", b"sealed").unwrap();

    let io = Arc::clone(&recovery.io);
    let generation = io
        .generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        + 1;
    let paused = super::lock(&io.lock);
    let writer_io = Arc::clone(&io);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let writer_dir = dir.clone();
    let writer = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        super::write_files(
            &writer_dir,
            None,
            &[super::ScrollbackWrite {
                key: "pane".to_owned(),
                json: secrecy::zeroize::Zeroizing::new(b"private".to_vec()),
                encrypted: true,
                hash: 1,
            }],
            &std::collections::BTreeSet::new(),
            &["pane".to_owned()].into(),
            Some(&secret),
            false,
            &writer_io,
            generation,
        );
    });
    started_rx.recv().unwrap();
    let cleaner = std::thread::spawn(move || {
        recovery.clear_encrypted_scrollback().unwrap();
    });
    while io.generation.load(std::sync::atomic::Ordering::Acquire) == generation {
        std::thread::yield_now();
    }
    drop(paused);
    writer.join().unwrap();
    cleaner.join().unwrap();

    let encrypted = std::fs::read_dir(dir.join(SCROLLBACK_DIR)).map_or(0, |entries| {
        entries
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "enc"))
            .count()
    });
    assert_eq!(encrypted, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "ssh")]
#[test]
fn malformed_key_is_not_installed_or_cached_as_a_successful_write() {
    let dir = tmp("ssh-malformed-key");
    let mut recovery = Recovery::new(dir.clone());
    let malformed = secrecy::SecretString::from("not-a-key");
    assert!(recovery.set_ssh_key(malformed.clone()).is_err());
    assert!(!recovery.has_ssh_key());
    let write = super::ScrollbackWrite {
        key: "pane".to_owned(),
        json: secrecy::zeroize::Zeroizing::new(b"private".to_vec()),
        encrypted: true,
        hash: 7,
    };
    let keep = ["pane".to_owned()].into();
    let generation = recovery
        .io
        .generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        + 1;
    super::write_files(
        &dir,
        None,
        &[write],
        &std::collections::BTreeSet::new(),
        &keep,
        Some(&malformed),
        false,
        &recovery.io,
        generation,
    );
    assert!(super::lock(&recovery.io.written).is_empty());
    assert!(!recovery::encrypted_scrollback_path(&dir, "pane").exists());

    let valid = fogu_session::new_recovery_key().unwrap();
    let generation = recovery
        .io
        .generation
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
        + 1;
    super::write_files(
        &dir,
        None,
        &[super::ScrollbackWrite {
            key: "pane".to_owned(),
            json: secrecy::zeroize::Zeroizing::new(b"private".to_vec()),
            encrypted: true,
            hash: 7,
        }],
        &std::collections::BTreeSet::new(),
        &keep,
        Some(&valid),
        false,
        &recovery.io,
        generation,
    );
    assert_eq!(super::lock(&recovery.io.written).get("pane"), Some(&7));
    assert!(recovery::encrypted_scrollback_path(&dir, "pane").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unchanged_layout_is_not_written_again() {
    let dir = tmp("debounce");
    let mut a = app(Config::default());
    two_tabs(&mut a);
    let mut rec = Recovery::new(dir.clone());
    a.save_recovery(&mut rec, false, true);
    std::fs::remove_file(dir.join(recovery::SESSION_FILE)).unwrap();
    a.save_recovery(&mut rec, false, true);
    assert!(
        !dir.join(recovery::SESSION_FILE).exists(),
        "nothing changed"
    );
    let active = a.active;
    a.tabs
        .iter_mut()
        .find(|t| t.id == active)
        .unwrap()
        .title_override = Some("new name".to_owned());
    a.save_recovery(&mut rec, false, true);
    assert!(dir.join(recovery::SESSION_FILE).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn only_the_first_instance_claims_the_saved_tabs() {
    let dir = tmp("instance-lock");
    std::fs::create_dir_all(&dir).unwrap();
    let InstanceClaim::Owner(lock) = super::claim_first(&dir) else {
        panic!("the first window owns the lock");
    };
    assert!(matches!(super::claim_first(&dir), InstanceClaim::Other));
    drop(lock);
    assert!(
        matches!(super::claim_first(&dir), InstanceClaim::Owner(_)),
        "the lock goes with the first window"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unusable_instance_lock_never_claims_ownership() {
    let dir = tmp("instance-lock-error");
    assert!(matches!(
        super::claim_first(&dir),
        InstanceClaim::Unconfirmed
    ));
}

#[test]
fn no_recovery_skips_an_existing_lock_and_starts_a_default_tab() {
    let dir = tmp("no-recovery-lock");
    std::fs::create_dir_all(&dir).unwrap();
    let InstanceClaim::Owner(lock) = super::claim_first(&dir) else {
        panic!("test owns the lock");
    };
    let runtime = Arc::new(SessionRuntime::new().unwrap());
    let (app, _task) = App::boot(
        runtime,
        Arc::new(Config::default()),
        RunOptions {
            state_dir: Some(dir.clone()),
            no_recovery: true,
            ..RunOptions::default()
        },
    );
    assert!(app.instance_lock.is_none() && app.recovery.is_none());
    assert_eq!(app.tabs.len(), 1);
    assert!(app.tabs[0].welcome.is_none() && !app.tabs[0].panes.is_empty());
    drop(lock);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quitting_while_the_restore_waits_for_the_keyring_keeps_the_saved_tabs() {
    let dir = tmp("pending");
    let mut first = app(Config::default());
    two_tabs(&mut first);
    save_now(&mut first, &dir);
    let saved = std::fs::read_to_string(dir.join("session.toml")).unwrap();

    let mut second = app(Config::default());
    let mut rec = Recovery::new(dir.clone());
    rec.pending_restore = true;
    second.recovery = Some(rec);
    second.forget_session();
    second.save_on_exit();
    assert_eq!(
        std::fs::read_to_string(dir.join("session.toml")).unwrap(),
        saved
    );
    let _ = std::fs::remove_dir_all(&dir);
}
