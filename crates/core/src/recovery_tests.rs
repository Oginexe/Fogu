#![expect(clippy::unwrap_used, reason = "tests")]

use super::*;
use crate::split::Side;

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fogu-recovery-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn spec(key: &str, profile: &str) -> PaneSpec {
    PaneSpec {
        key: key.to_owned(),
        profile_id: ProfileId(profile.to_owned()),
        ephemeral: None,
        cwd: Some("/srv".to_owned()),
    }
}

fn sample() -> RecoveryState {
    let mut layout = SplitTree::new(spec("a-1", "work"));
    layout.split(
        &spec("a-1", "work"),
        Side::Right,
        spec("a-2", "builtin:local:default"),
    );
    RecoveryState {
        version: VERSION,
        saved_at: 1_792_000_000,
        active_tab: 1,
        tabs: vec![
            TabState {
                title_override: Some("logs".to_owned()),
                color: Some(RgbColor::from_hex(0x0030_a46c)),
                background: TabBackground::None,
                focused: 1,
                layout,
            },
            TabState {
                title_override: None,
                color: None,
                background: TabBackground::Profile,
                focused: 0,
                layout: SplitTree::new(spec("b-1", "work")),
            },
        ],
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn session_round_trips_with_private_modes() {
    let dir = tmp("roundtrip");
    let state = sample();
    save(&dir, &state).unwrap();
    insta::assert_snapshot!(std::fs::read_to_string(dir.join(SESSION_FILE)).unwrap());
    assert_eq!(load(&dir).unwrap(), Some(state));
    save_scrollback(&dir, "a-1", b"{}").unwrap();
    #[cfg(unix)]
    {
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(SCROLLBACK_DIR)), 0o700);
        assert_eq!(mode(&dir.join(SESSION_FILE)), 0o600);
        assert_eq!(mode(&scrollback_path(&dir, "a-1")), 0o600);
    }
    clear(&dir).unwrap();
    assert!(load(&dir).unwrap().is_none());
    assert!(!dir.join(SCROLLBACK_DIR).exists());
    clear(&dir).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_files_are_refused_and_newer_ones_left_alone() {
    let dir = tmp("bad");
    std::fs::create_dir_all(&dir).unwrap();
    let write = |text: &str| std::fs::write(dir.join(SESSION_FILE), text).unwrap();
    write("not toml [");
    assert!(matches!(load(&dir), Err(RecoveryError::Parse(_))));
    let mut state = sample();
    state.tabs[0].layout = SplitTree::new(spec("../../etc/passwd", "work"));
    write(&toml::to_string(&state).unwrap());
    assert!(matches!(load(&dir), Err(RecoveryError::Invalid(_))));
    let mut newer = sample();
    newer.version = VERSION + 1;
    write(&toml::to_string(&newer).unwrap());
    assert!(load(&dir).unwrap().is_none());
    // Out-of-range indexes are clamped, not trusted.
    let mut wild = sample();
    wild.active_tab = 99;
    wild.tabs[1].focused = 7;
    write(&toml::to_string(&wild).unwrap());
    let loaded = load(&dir).unwrap().unwrap();
    assert_eq!((loaded.active_tab, loaded.tabs[1].focused), (1, 0));
    assert!(save_scrollback(&dir, "a/b", b"{}").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prune_drops_closed_panes_then_the_oldest_beyond_the_cap() {
    let dir = tmp("prune");
    for (key, len) in [("old", 40), ("mid", 40), ("new", 40), ("closed", 10)] {
        save_scrollback(&dir, key, &vec![b'x'; len]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
    let keep: BTreeSet<String> = ["old", "mid", "new"].map(str::to_owned).into();
    prune_scrollback(&dir, &keep, 90).unwrap();
    let left = |k: &str| scrollback_path(&dir, k).exists();
    assert!(!left("closed") && !left("old"));
    assert!(left("mid") && left("new"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keys_are_plain_names() {
    assert!(valid_key("18f2a-1b2c-3"));
    let traversal = ["../x", "..\\x", "/etc/x", "c:x", "x.json"];
    for bad in ["", "A", "a/b", "..", "a b", &"x".repeat(65)]
        .into_iter()
        .chain(traversal)
    {
        assert!(!valid_key(bad), "{bad:?}");
    }
}
