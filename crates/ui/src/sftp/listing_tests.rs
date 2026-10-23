use super::*;

fn entry(name: &str, kind: EntryKind, size: u64, mtime: u32) -> Entry {
    Entry {
        name: name.to_owned(),
        kind,
        size: Some(size),
        mtime: Some(mtime),
        mode: Some(0o644),
        uid: None,
        gid: None,
        link_target: None,
        link_kind: None,
    }
}

fn sample() -> Listing {
    let mut l = Listing::new(false);
    let mut link = entry("linkdir", EntryKind::Symlink, 7, 5);
    link.link_kind = Some(EntryKind::Dir);
    l.replace(
        vec![
            entry("b.txt", EntryKind::File, 300, 10),
            entry("A.txt", EntryKind::File, 100, 30),
            entry("zdir", EntryKind::Dir, 4096, 1),
            entry(".hidden", EntryKind::File, 1, 1),
            entry("c.bin", EntryKind::File, 200, 20),
            link,
        ],
        false,
    );
    l
}

fn names(l: &Listing) -> Vec<&str> {
    l.visible().iter().map(|e| e.name.as_str()).collect()
}

#[test]
fn sort_orders_keep_directories_first() {
    let mut l = sample();
    assert_eq!(
        names(&l),
        ["linkdir", "zdir", "A.txt", "b.txt", "c.bin"],
        "name, case-insensitive"
    );
    l.sort_by(SortKey::Name);
    assert_eq!(names(&l), ["zdir", "linkdir", "c.bin", "b.txt", "A.txt"]);
    l.sort_by(SortKey::Size);
    assert_eq!(names(&l), ["linkdir", "zdir", "A.txt", "c.bin", "b.txt"]);
    l.sort_by(SortKey::Size);
    assert_eq!(names(&l), ["zdir", "linkdir", "b.txt", "c.bin", "A.txt"]);
    l.sort_by(SortKey::Modified);
    assert_eq!(names(&l), ["zdir", "linkdir", "b.txt", "c.bin", "A.txt"]);
}

#[test]
fn hidden_toggle_and_filter() {
    let mut l = sample();
    assert!(!names(&l).contains(&".hidden"));
    assert_eq!(l.hidden_count(), 1);
    l.show_hidden = true;
    assert!(names(&l).contains(&".hidden"));
    assert_eq!(l.hidden_count(), 0);
    l.filter = "TX".into();
    assert_eq!(names(&l), ["A.txt", "b.txt"]);
    l.filter = "nothing".into();
    assert_eq!(names(&l).len(), 0);
}

#[test]
fn click_ctrl_and_shift_selection() {
    let mut l = sample();
    l.click("A.txt", ClickMods::default());
    assert_eq!(l.selected.iter().collect::<Vec<_>>(), ["A.txt"]);
    l.click(
        "c.bin",
        ClickMods {
            ctrl: true,
            shift: false,
        },
    );
    assert_eq!(l.selected.len(), 2);
    l.click(
        "A.txt",
        ClickMods {
            ctrl: true,
            shift: false,
        },
    );
    assert_eq!(l.selected.iter().collect::<Vec<_>>(), ["c.bin"]);
    // Anchor is now A.txt (last ctrl-click); shift selects the visible range.
    l.click("A.txt", ClickMods::default());
    l.click(
        "zdir",
        ClickMods {
            ctrl: false,
            shift: true,
        },
    );
    let mut got: Vec<&str> = l.selected.iter().map(String::as_str).collect();
    got.sort_unstable();
    assert_eq!(got, ["A.txt", "zdir"]);
    let in_order: Vec<&str> = l
        .selected_entries()
        .iter()
        .map(|e| e.name.as_str())
        .collect();
    assert_eq!(in_order, ["zdir", "A.txt"]);
}

#[test]
fn keyboard_cursor_moves_and_clamps() {
    let mut l = sample();
    assert_eq!(l.move_cursor(1), Some(0));
    assert_eq!(l.cursor.as_deref(), Some("linkdir"));
    assert_eq!(l.move_cursor(10), Some(4));
    assert_eq!(l.move_cursor(-1), Some(3));
    assert_eq!(l.selected.iter().collect::<Vec<_>>(), ["b.txt"]);
    assert_eq!(l.move_cursor(-10), Some(0));
}

#[test]
fn refresh_keeps_surviving_selection() {
    let mut l = sample();
    l.click("A.txt", ClickMods::default());
    l.replace(vec![entry("b.txt", EntryKind::File, 1, 1)], true);
    assert_eq!(l.selected.len(), 0);
    assert!(l.cursor.is_none());
    assert!(l.truncated);
}

#[test]
fn formatting_helpers() {
    assert_eq!(human_bytes(0), "0 B");
    assert_eq!(human_bytes(1023), "1023 B");
    assert_eq!(human_bytes(1536), "1.5 KiB");
    assert_eq!(human_bytes(5 << 30), "5.0 GiB");
    let mut e = entry("x", EntryKind::File, 1, 0);
    for (mode, kind, want) in [
        (0o644, EntryKind::File, "-rw-r--r--"),
        (0o755, EntryKind::Dir, "drwxr-xr-x"),
        (0o4755, EntryKind::File, "-rwsr-xr-x"),
        (0o1777, EntryKind::Dir, "drwxrwxrwt"),
        (0o2644, EntryKind::File, "-rw-r-Sr--"),
        (0o777, EntryKind::Symlink, "lrwxrwxrwx"),
    ] {
        e.mode = Some(mode);
        e.kind = kind;
        assert_eq!(permissions(&e), want, "{mode:o}");
    }
    e.mode = None;
    assert_eq!(permissions(&e), "?");
    e.mtime = Some(0);
    assert_eq!(modified(&e), "1970-01-01 00:00");
    e.mtime = Some(1_792_067_696); // 2026-10-15 12:34:56 UTC
    assert_eq!(modified(&e), "2026-10-15 12:34");
    e.mtime = Some(951_782_400); // leap day 2000
    assert_eq!(modified(&e), "2000-02-29 00:00");
    let shown = shown_name(&entry("we\x1bird", EntryKind::Dir, 0, 0));
    assert_eq!(shown, "we\\x1bird/");
    assert_eq!(human_size(&entry("d", EntryKind::Dir, 4096, 0)), "");
    let first = sample().visible().first().map(|e| e.name.clone()).unwrap();
    assert_eq!(first, "linkdir");
}

/// The names a malicious server can send: the reducer, the view helpers and the
/// breadcrumb must accept them without a panic and show nothing unescaped.
#[test]
fn hostile_listing_is_accepted_and_shown_escaped() {
    let long = "n".repeat(4096);
    let names = [
        "..",
        "a/b",
        ".",
        "",
        "evil\x1b]52;c;AAAA\x07",
        "-rf",
        long.as_str(),
        "l",
        "ok",
        "evil\u{202e}gpj.exe",
        "nul\0x",
    ];
    let mut l = Listing::new(true);
    let mut entries: Vec<Entry> = names
        .iter()
        .enumerate()
        .map(|(i, n)| entry(n, EntryKind::File, u64::MAX - i as u64, u32::MAX))
        .collect();
    entries[7].kind = EntryKind::Symlink;
    entries[7].link_kind = Some(EntryKind::Dir);
    entries[7].link_target = Some(".".into());
    entries[0].mode = Some(u32::MAX);
    l.replace(entries, true);
    for key in [
        SortKey::Name,
        SortKey::Size,
        SortKey::Modified,
        SortKey::Mode,
    ] {
        l.sort_by(key);
        l.sort_by(key);
    }
    assert_eq!(l.visible().len(), names.len());
    for e in l.visible() {
        for text in [shown_name(e), human_size(e), permissions(e), modified(e)] {
            assert!(!text.chars().any(char::is_control), "{text:?}");
            assert!(!text.contains('\u{202e}'), "{text:?}");
            assert!(text.chars().count() <= 257, "{}", text.len());
        }
    }
    for name in names {
        l.click(name, ClickMods::default());
    }
    l.filter = "evil".into();
    assert_eq!(l.visible().len(), 2);
    for path in [
        "/etc/../../tmp",
        "",
        "/",
        "//",
        "rel",
        "/evil\x1b]52;c;AAAA\x07/x",
    ] {
        for s in super::super::breadcrumb::segments(path) {
            assert!(!s.label.chars().any(char::is_control), "{path:?}");
        }
        let _ = super::super::breadcrumb::parent(path);
    }
}
