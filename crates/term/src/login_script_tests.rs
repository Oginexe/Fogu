use fogu_core::LoginScript;

use super::*;

fn script(expect: &str, send: &str, is_regex: bool, optional: bool) -> LoginScript {
    LoginScript {
        expect: expect.to_owned(),
        send: send.to_owned(),
        is_regex,
        optional,
    }
}

fn matcher(scripts: &[LoginScript]) -> LoginScriptMatcher {
    let (m, problems) = LoginScriptMatcher::new(scripts, b"\n");
    assert!(problems.is_empty(), "{problems:?}");
    m
}

fn text(replies: &[Vec<u8>]) -> Vec<String> {
    replies
        .iter()
        .map(|r| String::from_utf8_lossy(r).into_owned())
        .collect()
}

#[test]
fn rules_fire_in_order_once_each() {
    let mut m = matcher(&[
        script("login:", "me", false, false),
        script("Password:", "pw", false, false),
    ]);
    assert!(text(&m.process(b"Password: ")).is_empty(), "out of order");
    assert_eq!(text(&m.process(b"login: ")), ["me\n"]);
    assert!(!m.done());
    assert_eq!(text(&m.process(b"Password: ")), ["pw\n"]);
    assert!(m.done());
    assert_eq!(m.process(b"login: Password: "), Vec::<Vec<u8>>::new());
}

#[test]
fn split_output_and_coloured_prompts_match() {
    let mut m = matcher(&[script(r"\$ $", "uname -a", true, false)]);
    let none: Vec<Vec<u8>> = Vec::new();
    assert_eq!(m.process(b"\x1b[1;32muser@host\x1b[0m:~\x1b]0;title"), none);
    assert_eq!(text(&m.process(b"\x07\x1b[34m$ ")), ["uname -a\n"]);
}

#[test]
fn a_match_consumes_the_prompt() {
    let mut m = matcher(&[
        script("$ ", "one", false, false),
        script("$ ", "two", false, false),
    ]);
    assert_eq!(text(&m.process(b"$ ")), ["one\n"]);
    assert_eq!(text(&m.process(b"output\n$ ")), ["two\n"]);
}

#[test]
fn optional_rules_are_skipped_when_a_later_one_matches() {
    let mut m = matcher(&[
        script("Accept?", "y", false, true),
        script("$ ", "ls", false, false),
    ]);
    assert_eq!(text(&m.process(b"$ ")), ["ls\n"]);
    assert!(m.done());
    let mut m = matcher(&[
        script("Accept?", "y", false, true),
        script("$ ", "ls", false, false),
    ]);
    assert_eq!(text(&m.process(b"Accept? ... $ ")), ["y\n", "ls\n"]);
}

#[test]
fn empty_expect_sends_when_first_in_line() {
    let mut m = matcher(&[
        script("", "first", false, false),
        script("$ ", "ls", false, false),
        script("", "after", false, false),
    ]);
    assert_eq!(text(&m.process(b"")), ["first\n"]);
    assert_eq!(text(&m.process(b"$ ")), ["ls\n", "after\n"]);
    assert!(m.done());
}

#[test]
fn escapes_are_unescaped() {
    assert_eq!(unescape(r"a\tb\x41é\e\q\\"), "a\tbAé\x1bq\\".as_bytes());
    assert_eq!(unescape(r"\x4"), b"x4", "short hex stays text");
    assert_eq!(unescape("end\\"), b"end\\");
    let mut m = matcher(&[script(r"ok\x21", r"\r", false, false)]);
    assert_eq!(text(&m.process(b"ok!")), ["\r\n"]);
}

#[test]
fn invalid_regex_is_reported_and_dropped() {
    let (mut m, problems) = LoginScriptMatcher::new(
        &[
            script("(", "x", true, false),
            script("$", "y", false, false),
        ],
        b"\r",
    );
    assert_eq!(problems.len(), 1);
    assert!(
        problems[0].starts_with("login script 1: invalid regex"),
        "{problems:?}"
    );
    assert_eq!(text(&m.process(b"$")), ["y\r"]);
}

#[test]
fn the_window_stays_bounded() {
    let mut m = matcher(&[script("never", "x", false, false)]);
    for _ in 0..100 {
        m.process(&[b'a'; 1000]);
    }
    assert!(m.window.len() <= WINDOW);
}
