use super::*;

fn scan_str(scanner: &mut OscScanner, osc: &str) -> Vec<OscEvent> {
    scanner.scan(format!("\x1b]{osc}\x07").as_bytes())
}

#[test]
fn osc7_parses_host_and_percent_decoded_path() {
    let mut s = OscScanner::new();
    let events = scan_str(&mut s, "7;file://myhost/home/me/My%20Dir");
    assert_eq!(
        events,
        vec![OscEvent::Cwd {
            host: "myhost".to_owned(),
            path: PathBuf::from("/home/me/My Dir"),
        }]
    );
}

#[test]
fn osc7_with_empty_host() {
    let mut s = OscScanner::new();
    let events = scan_str(&mut s, "7;file:///tmp");
    assert_eq!(
        events,
        vec![OscEvent::Cwd {
            host: String::new(),
            path: PathBuf::from("/tmp"),
        }]
    );
}

#[test]
fn osc1337_current_dir() {
    let mut s = OscScanner::new();
    let events = scan_str(&mut s, "1337;CurrentDir=/var/log");
    assert_eq!(
        events,
        vec![OscEvent::Cwd {
            host: String::new(),
            path: PathBuf::from("/var/log"),
        }]
    );
}

#[test]
fn osc133_prompt_marks() {
    let mut s = OscScanner::new();
    assert_eq!(
        scan_str(&mut s, "133;A"),
        vec![OscEvent::Prompt(PromptMark::PromptStart)]
    );
    assert_eq!(
        scan_str(&mut s, "133;B"),
        vec![OscEvent::Prompt(PromptMark::CommandStart)]
    );
    assert_eq!(
        scan_str(&mut s, "133;C"),
        vec![OscEvent::Prompt(PromptMark::OutputStart)]
    );
    assert_eq!(
        scan_str(&mut s, "133;D;0"),
        vec![OscEvent::Prompt(PromptMark::CommandFinished {
            exit_code: Some(0)
        })]
    );
    assert_eq!(
        scan_str(&mut s, "133;D"),
        vec![OscEvent::Prompt(PromptMark::CommandFinished {
            exit_code: None
        })]
    );
}

#[test]
fn osc9_plain_notify() {
    let mut s = OscScanner::new();
    let events = scan_str(&mut s, "9;build finished");
    assert_eq!(
        events,
        vec![OscEvent::Notify {
            title: None,
            body: "build finished".to_owned(),
        }]
    );
}

#[test]
fn osc9_4_progress_states() {
    let mut s = OscScanner::new();
    assert_eq!(scan_str(&mut s, "9;4;0;0"), vec![OscEvent::Progress(None)]);
    assert_eq!(
        scan_str(&mut s, "9;4;1;42"),
        vec![OscEvent::Progress(Some(42))]
    );
    assert_eq!(scan_str(&mut s, "9;4;3"), vec![OscEvent::Progress(None)]);
    assert_eq!(
        scan_str(&mut s, "9;4;1;250"),
        vec![OscEvent::Progress(Some(100))]
    );
    assert_eq!(scan_str(&mut s, "9;4"), vec![OscEvent::Progress(None)]);
}

#[test]
fn osc777_notify_with_title() {
    let mut s = OscScanner::new();
    let events = scan_str(&mut s, "777;notify;Title;Body text");
    assert_eq!(
        events,
        vec![OscEvent::Notify {
            title: Some("Title".to_owned()),
            body: "Body text".to_owned(),
        }]
    );
}

#[test]
fn unsupported_osc_code_is_ignored() {
    let mut s = OscScanner::new();
    assert_eq!(scan_str(&mut s, "52;c;?"), Vec::new());
    assert_eq!(scan_str(&mut s, "4;1;rgb:ff/00/00"), Vec::new());
}

#[test]
fn sequence_split_across_two_chunks() {
    let mut s = OscScanner::new();
    assert_eq!(s.scan(b"\x1b]7;file://h/"), Vec::new());
    let events = s.scan(b"home\x07");
    assert_eq!(
        events,
        vec![OscEvent::Cwd {
            host: "h".to_owned(),
            path: PathBuf::from("/home"),
        }]
    );
}

#[test]
fn sequence_split_mid_escape_and_mid_st_terminator() {
    let mut s = OscScanner::new();
    // Split right after the ESC that starts the sequence.
    assert_eq!(s.scan(b"\x1b"), Vec::new());
    assert_eq!(s.scan(b"]1337;CurrentDir=/a"), Vec::new());
    // ST terminator (`ESC \`) split between the two bytes.
    assert_eq!(s.scan(b"\x1b"), Vec::new());
    let events = s.scan(b"\\");
    assert_eq!(
        events,
        vec![OscEvent::Cwd {
            host: String::new(),
            path: PathBuf::from("/a"),
        }]
    );
}

#[test]
fn oversized_sequence_is_discarded_and_buffer_stays_bounded() {
    let mut s = OscScanner::new();
    let huge = "x".repeat(MAX_SEQUENCE + 1000);
    let payload = format!("\x1b]9;{huge}\x07");
    let events = s.scan(payload.as_bytes());
    assert_eq!(events, Vec::new());
    assert!(s.buf.len() <= MAX_SEQUENCE);
}

#[test]
fn scanner_resyncs_after_a_discarded_sequence() {
    let mut s = OscScanner::new();
    let huge = "x".repeat(MAX_SEQUENCE + 10);
    let mut payload = format!("\x1b]9;{huge}\x07").into_bytes();
    payload.extend_from_slice(b"\x1b]9;hello\x07");
    let events = s.scan(&payload);
    assert_eq!(
        events,
        vec![OscEvent::Notify {
            title: None,
            body: "hello".to_owned(),
        }]
    );
}

#[test]
fn invalid_st_abandons_payload_without_losing_the_next_sequence() {
    let mut s = OscScanner::new();
    // `ESC ] 9 ; x ESC X` (not a valid ST) followed immediately by a fresh, valid sequence.
    let events = s.scan(b"\x1b]9;x\x1bX\x1b]9;ok\x07");
    assert_eq!(
        events,
        vec![OscEvent::Notify {
            title: None,
            body: "ok".to_owned(),
        }]
    );
}

#[test]
fn non_osc_escape_sequences_produce_no_events() {
    let mut s = OscScanner::new();
    // CSI, plain text and a bare ESC must never be mistaken for an OSC payload.
    assert_eq!(s.scan(b"\x1b[31mhello\x1b[0m"), Vec::new());
}

#[test]
fn fuzz_regression_arbitrary_bytes_never_panics() {
    let mut s = OscScanner::new();
    let mut data = Vec::new();
    for i in 0..5000_u32 {
        data.push(i.to_le_bytes()[0]);
    }
    let _ = s.scan(&data);
    assert!(s.buf.len() <= MAX_SEQUENCE);
}
