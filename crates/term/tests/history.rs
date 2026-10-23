//! Scrollback capture/restore as inert runs: round trip, inert restore, validation.

use fogu_term::history::{
    HistoryError, MAX_BYTES, Run, SavedColor, SavedHistory, SavedRow, VERSION, flag, validate,
};
use fogu_term::{TermEvent, TermHandle, WORD_SEPARATORS};

fn term(cols: u16, rows: u16) -> TermHandle {
    TermHandle::new(cols, rows, 1000, WORD_SEPARATORS)
}

/// 200 lines with colours (named, indexed, rgb), styles, wide and combining chars, and long
/// lines that wrap at 40 columns.
fn busy_output() -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..200u32 {
        let line = match i % 5 {
            0 => format!(
                "\x1b[1;31mred {i}\x1b[0m plain \x1b[38;5;{}midx\x1b[0m",
                i % 256
            ),
            1 => format!(
                "\x1b[38;2;10;{};200m\x1b[44mrgb on blue {i}\x1b[0m",
                i % 256
            ),
            2 => format!("wide 日本語 {i} e\u{301}\x1b[3;4;9mstyled\x1b[0m"),
            3 => format!("long {} end", "x".repeat(90 + (i as usize % 7))),
            _ => format!("\x1b[2;7mdim inverse\x1b[0m   {i}"),
        };
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[test]
fn capture_restore_capture_round_trips() {
    let mut original = term(40, 24);
    original.feed(&busy_output());
    let saved = original.capture_history(1000, 7);
    assert!(
        saved.rows.len() > 200,
        "wrapped lines add rows: {}",
        saved.rows.len()
    );
    assert!(saved.rows.iter().any(|r| r.wrapped));
    let mut fresh = term(40, 24);
    fresh.restore_history(&saved);
    assert_eq!(fresh.capture_history(1000, 7), saved);
}

#[test]
fn max_lines_keeps_the_newest_rows() {
    let mut t = term(20, 5);
    for i in 0..50 {
        t.feed(format!("line {i}\r\n").as_bytes());
    }
    let saved = t.capture_history(3, 0);
    let texts: Vec<&str> = saved.rows.iter().map(|r| r.runs[0].text.as_str()).collect();
    assert_eq!(texts, ["line 47", "line 48", "line 49"]);
}

#[test]
fn json_shape_is_readable() {
    let mut t = term(20, 4);
    t.feed(b"\x1b[1;32mok\x1b[0m done\r\n");
    let saved = t.capture_history(10, 1_792_000_000);
    insta::assert_snapshot!(serde_json::to_string_pretty(&saved).unwrap());
}

#[test]
fn escape_sequences_in_saved_text_restore_as_replacement_chars() {
    // Sanity: the same bytes fed for real do ask for a clipboard write.
    let mut live = term(20, 4);
    live.feed(b"\x1b]52;c;QUJD\x07");
    assert!(
        live.drain_events()
            .iter()
            .any(|e| matches!(e, TermEvent::ClipboardStore { .. }))
    );
    let saved = SavedHistory {
        version: VERSION,
        cols: 20,
        captured_at: 0,
        rows: vec![SavedRow {
            runs: vec![Run {
                text: "a\x1b]52;c;QUJD\x07b".to_owned(),
                fg: SavedColor::Default,
                bg: SavedColor::Default,
                flags: 0,
            }],
            wrapped: false,
        }],
    };
    assert_eq!(validate(&saved, 100, MAX_BYTES), Err(HistoryError::Control));
    let mut t = term(20, 4);
    t.restore_history(&saved);
    assert_eq!(t.drain_events().len(), 0, "no events from restored text");
    let text = t.dump_grid();
    assert!(text.contains("a\u{fffd}]52;c;QUJD\u{fffd}b"), "{text}");
}

#[test]
fn validate_bounds_and_style_bits() {
    let row = |text: &str, flags| SavedRow {
        runs: vec![Run {
            text: text.to_owned(),
            fg: SavedColor::Named(3),
            bg: SavedColor::Default,
            flags,
        }],
        wrapped: false,
    };
    let ok = SavedHistory {
        version: VERSION,
        cols: 80,
        captured_at: 0,
        rows: vec![row("hi", flag::BOLD | flag::STRIKE)],
    };
    assert_eq!(validate(&ok, 10, 100), Ok(()));
    let with = |f: &dyn Fn(&mut SavedHistory)| {
        let mut h = ok.clone();
        f(&mut h);
        validate(&h, 10, 100)
    };
    assert_eq!(with(&|h| h.version = 9), Err(HistoryError::Version(9)));
    assert_eq!(with(&|h| h.cols = 1), Err(HistoryError::Cols(1)));
    assert_eq!(
        with(&|h| h.rows = vec![row("x", 0); 11]),
        Err(HistoryError::TooManyRows(11))
    );
    assert_eq!(
        with(&|h| h.rows = vec![row(&"y".repeat(101), 0)]),
        Err(HistoryError::TooLarge(101))
    );
    assert_eq!(
        with(&|h| h.rows = vec![row("z", 1 << 9)]),
        Err(HistoryError::Style)
    );
    assert_eq!(
        with(&|h| h.rows[0].runs[0].fg = SavedColor::Named(16)),
        Err(HistoryError::Style)
    );
}

#[test]
fn the_primary_screen_is_captured_while_the_alternate_one_shows() {
    let mut t = term(20, 4);
    t.feed(b"shell line\r\n$ vim\r\n\x1b[?1049h\x1b[Hvim screen");
    t.select_all();
    let selected = t.selection_text();
    assert!(selected.is_some());
    let saved = t.capture_history(10, 0);
    assert_eq!(
        t.selection_text(),
        selected,
        "the periodic capture keeps the selection"
    );
    let texts: Vec<&str> = saved.rows.iter().map(|r| r.runs[0].text.as_str()).collect();
    assert_eq!(texts, ["shell line", "$ vim"]);
    // The alternate screen is untouched and still shown.
    assert!(t.dump_grid().contains("vim screen"), "{}", t.dump_grid());
    t.feed(b"\x1b[?1049l");
    assert!(t.dump_grid().contains("shell line"), "{}", t.dump_grid());
}
