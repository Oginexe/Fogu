//! Headless tests of `TermHandle`: grid state as `insta` snapshots, replies as exact bytes.

use std::fmt::Write as _;

use fogu_term::{
    CellFlags, Color, NamedColor, Rgb, Scroll, TermEvent, TermHandle, TermMode, WORD_SEPARATORS,
};

fn term(cols: u16, rows: u16) -> TermHandle {
    TermHandle::new(cols, rows, 100, WORD_SEPARATORS)
}

fn fed(cols: u16, rows: u16, bytes: &[u8]) -> TermHandle {
    let mut t = term(cols, rows);
    t.feed(bytes);
    t
}

fn pty_writes(t: &mut TermHandle) -> Vec<Vec<u8>> {
    t.drain_events()
        .into_iter()
        .filter_map(|e| match e {
            TermEvent::PtyWrite(bytes) => Some(bytes),
            _ => None,
        })
        .collect()
}

/// First row as "char fg bg flags" lines, skipping blank cells.
fn attrs_of_first_row(t: &TermHandle) -> String {
    let snap = t.snapshot();
    let mut out = String::new();
    for cell in snap
        .rows()
        .next()
        .unwrap_or_default()
        .iter()
        .filter(|c| c.ch != ' ')
    {
        let _ = writeln!(
            out,
            "{:?} fg={:?} bg={:?} flags={:?}",
            cell.ch, cell.fg, cell.bg, cell.flags
        );
    }
    out
}

#[test]
fn sgr_colors() {
    let t = fed(
        20,
        2,
        b"\x1b[31mred\x1b[0m \x1b[1;38;5;208mB\x1b[0m \x1b[3;48;2;1;2;3mT\x1b[0m",
    );
    insta::assert_snapshot!(t.dump_grid());
    insta::assert_snapshot!(attrs_of_first_row(&t));
}

#[test]
fn sgr_underline_kinds_and_color() {
    let t = fed(
        10,
        1,
        b"\x1b[4:3;58;2;255;0;0mc\x1b[0m\x1b[4:2md\x1b[0m\x1b[9;2;7;8ms",
    );
    let snap = t.snapshot();
    let mut cells = snap.cells.iter();
    let curly = cells.next().map(|c| (c.flags, c.underline_color));
    assert_eq!(
        curly,
        Some((
            CellFlags::UNDERCURL,
            Some(Color::Spec(Rgb { r: 255, g: 0, b: 0 }))
        ))
    );
    assert_eq!(
        cells.next().map(|c| c.flags),
        Some(CellFlags::DOUBLE_UNDERLINE)
    );
    let all = CellFlags::STRIKEOUT | CellFlags::DIM | CellFlags::INVERSE | CellFlags::HIDDEN;
    assert_eq!(cells.next().map(|c| c.flags), Some(all));
}

#[test]
fn cr_lf() {
    let t = fed(10, 4, b"one\r\ntwo\nthree\rTH");
    insta::assert_snapshot!(t.dump_grid());
}

#[test]
fn clear_and_home() {
    let t = fed(10, 3, b"garbage\r\nmore\x1b[2J\x1b[Hfresh");
    insta::assert_snapshot!(t.dump_grid());
    let cursor = t.snapshot().cursor;
    assert_eq!((cursor.row, cursor.col, cursor.visible), (0, 5, true));
}

#[test]
fn resize_reflows() {
    let mut t = fed(10, 3, b"0123456789abcdef");
    insta::assert_snapshot!("resize_before", t.dump_grid());
    t.resize(20, 3);
    insta::assert_snapshot!("resize_wider", t.dump_grid());
    t.resize(5, 4);
    // Lines above the cursor's reflowed line move into history (alacritty behaviour).
    insta::assert_snapshot!("resize_narrower", t.dump_grid());
    assert_eq!(t.snapshot().history_len, 3);
    t.scroll_display(Scroll::Top);
    insta::assert_snapshot!("resize_narrower_top", t.dump_grid());
}

#[test]
fn resize_to_one_column_with_wide_chars_terminates() {
    // fuzz regression: a 1-column reflow of a wide char looped forever (OOM)
    let mut t = fed(10, 2, "日本".as_bytes());
    t.resize(0, 0);
    assert_eq!(t.snapshot().cols, 2);
}

#[test]
fn wide_chars_take_two_cells() {
    let t = fed(10, 2, "日本😀x".as_bytes());
    insta::assert_snapshot!(t.dump_grid());
    let snap = t.snapshot();
    let flags: Vec<CellFlags> = snap.cells.iter().take(7).map(|c| c.flags).collect();
    let (w, s, n) = (
        CellFlags::WIDE_CHAR,
        CellFlags::WIDE_CHAR_SPACER,
        CellFlags::empty(),
    );
    assert_eq!(flags, [w, s, w, s, w, s, n]);
    assert_eq!(snap.cursor.col, 7);
}

#[test]
fn scrollback_past_one_screen() {
    let mut t = term(8, 3);
    for i in 0..6 {
        t.feed(format!("line{i}\r\n").as_bytes());
    }
    insta::assert_snapshot!("scrollback_bottom", t.dump_grid());
    let snap = t.snapshot();
    assert_eq!((snap.history_len, snap.display_offset), (4, 0));

    t.scroll_display(Scroll::Top);
    insta::assert_snapshot!("scrollback_top", t.dump_grid());
    let snap = t.snapshot();
    assert_eq!(snap.display_offset, 4);
    assert!(
        !snap.cursor.visible,
        "cursor is below the scrolled viewport"
    );

    t.scroll_display(Scroll::Bottom);
    assert_eq!(t.snapshot().display_offset, 0);
}

#[test]
fn alt_screen_enter_leave() {
    let mut t = fed(10, 2, b"primary");
    t.feed(b"\x1b[?1049h\x1b[Halt");
    assert!(t.mode().contains(TermMode::ALT_SCREEN));
    insta::assert_snapshot!("alt_screen_inside", t.dump_grid());
    t.feed(b"\x1b[?1049l");
    assert!(!t.mode().contains(TermMode::ALT_SCREEN));
    insta::assert_snapshot!("alt_screen_after", t.dump_grid());
}

#[test]
fn da_and_dsr_reply_with_fixed_bytes() {
    let mut t = fed(10, 3, b"ab\x1b[c\x1b[5n\x1b[6n");
    assert_eq!(
        pty_writes(&mut t),
        [
            b"\x1b[?6c".to_vec(),
            b"\x1b[0n".to_vec(),
            b"\x1b[1;3R".to_vec()
        ]
    );
}

#[test]
fn title_is_sanitized_and_capped() {
    let mut t = fed(10, 2, b"\x1b]2;evil\x07");
    // C1 control (U+009B CSI) inside an OSC title, then an over-long title.
    t.feed("\x1b]0;a\u{9b}b\x1b\\".as_bytes());
    t.feed(format!("\x1b]2;{}\x07", "x".repeat(1000)).as_bytes());
    let titles: Vec<String> = t
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            TermEvent::Title(s) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(
        titles,
        ["evil".to_owned(), "ab".to_owned(), "x".repeat(256)]
    );
}

#[test]
fn osc52_read_produces_nothing() {
    let mut t = fed(10, 2, b"\x1b]52;c;?\x07\x1b]52;p;?\x1b\\");
    assert_eq!(t.drain_events(), []);
}

#[test]
fn osc52_write_is_forwarded_for_policy() {
    // "hello" in base64.
    let mut t = fed(10, 2, b"\x1b]52;c;aGVsbG8=\x07");
    assert_eq!(
        t.drain_events(),
        [TermEvent::ClipboardStore {
            target: fogu_term::ClipboardType::Clipboard,
            payload: "hello".to_owned(),
            len: 5,
        }]
    );
}

#[test]
fn color_query_answers_from_palette() {
    let mut t = term(10, 2);
    let mut palette = fogu_term::default_palette();
    if let Some(bg) = palette.get_mut(NamedColor::Background as usize) {
        *bg = Rgb {
            r: 0x12,
            g: 0x34,
            b: 0x56,
        };
    }
    t.set_palette(palette);
    t.feed(b"\x1b]11;?\x07\x1b]4;1;?\x07");
    assert_eq!(
        pty_writes(&mut t),
        [
            b"\x1b]11;rgb:1212/3434/5656\x07".to_vec(),
            b"\x1b]4;1;rgb:cdcd/0000/0000\x07".to_vec()
        ]
    );
}

#[test]
fn text_area_size_queries_are_answered() {
    let mut t = term(80, 24);
    t.set_cell_size_px(9, 18);
    t.feed(b"\x1b[18t\x1b[14t");
    assert_eq!(
        pty_writes(&mut t),
        [b"\x1b[8;24;80t".to_vec(), b"\x1b[4;432;720t".to_vec()]
    );
}

#[test]
fn no_reply_to_title_report_or_decrqss() {
    // CSI 21 t (title report), DECRQSS, XTGETTCAP: must never echo attacker strings.
    let mut t = fed(
        10,
        2,
        b"\x1b]2;rm -rf ~\x07\x1b[21t\x1bP$qm\x1b\\\x1bP+q544e\x1b\\",
    );
    assert_eq!(pty_writes(&mut t), Vec::<Vec<u8>>::new());
}

#[test]
fn bell_is_reported() {
    let mut t = fed(10, 2, b"\x07");
    assert_eq!(t.drain_events(), [TermEvent::Bell]);
}

#[test]
fn synchronized_update_defers_until_end() {
    let mut t = fed(10, 2, b"\x1b[?2026hhidden");
    assert!(t.sync_timeout().is_some());
    assert_eq!(t.dump_grid(), "\n\n");
    t.feed(b"\x1b[?2026l");
    assert!(t.sync_timeout().is_none());
    assert_eq!(t.dump_grid(), "hidden\n\n");
}

#[test]
fn large_feed_is_chunked_without_loss() {
    let mut t = TermHandle::new(10, 2, 0, WORD_SEPARATORS);
    let mut bytes = vec![b'a'; 200 * 1024];
    bytes.extend_from_slice(b"\r\nend");
    t.feed(&bytes);
    assert_eq!(t.dump_grid(), "aaaaaaaaaa\nend\n");
}

#[test]
fn a_refresh_reuses_the_cell_buffer() {
    let t = fed(80, 24, b"hello");
    let first = t.snapshot();
    let buffer = first.cells.as_ptr();
    let again = t.snapshot_reusing(first.cells);
    assert_eq!(again.cells.as_ptr(), buffer);
    assert_eq!(again, t.snapshot());
}
