use super::*;
use crate::{TermHandle, WORD_SEPARATORS};

/// `(matched text, uri, kind)`.
type Expected<'a> = (&'a str, &'a str, LinkKind);

/// `(text, expected links as (matched text, uri, kind))`.
#[test]
fn detect_links_table() {
    use LinkKind::{Path, Url};
    let cases: &[(&str, &[Expected<'_>])] = &[
        (
            "see https://example.com now",
            &[("https://example.com", "https://example.com", Url)],
        ),
        (
            "https://example.com.",
            &[("https://example.com", "https://example.com", Url)],
        ),
        (
            "(https://example.com)",
            &[("https://example.com", "https://example.com", Url)],
        ),
        (
            "https://en.wikipedia.org/wiki/Rust_(language)",
            &[(
                "https://en.wikipedia.org/wiki/Rust_(language)",
                "https://en.wikipedia.org/wiki/Rust_(language)",
                Url,
            )],
        ),
        (
            "go to www.rust-lang.org, ok",
            &[("www.rust-lang.org", "https://www.rust-lang.org", Url)],
        ),
        (
            "http://a.b/c?d=1&e=2#f",
            &[("http://a.b/c?d=1&e=2#f", "http://a.b/c?d=1&e=2#f", Url)],
        ),
        (
            "\"https://x.io/q\"",
            &[("https://x.io/q", "https://x.io/q", Url)],
        ),
        ("<https://x.io>", &[("https://x.io", "https://x.io", Url)]),
        (
            "ftp://files.lan/a.iso",
            &[("ftp://files.lan/a.iso", "ftp://files.lan/a.iso", Url)],
        ),
        (
            "mailto:me@example.com!",
            &[("mailto:me@example.com", "mailto:me@example.com", Url)],
        ),
        (
            "file:///etc/hosts",
            &[("file:///etc/hosts", "file:///etc/hosts", Url)],
        ),
        (
            "host 192.0.2.101 up",
            &[("192.0.2.101", "http://192.0.2.101", Url)],
        ),
        (
            "listen 10.0.0.7:44933",
            &[("10.0.0.7:44933", "http://10.0.0.7:44933", Url)],
        ),
        ("999.1.1.1", &[]),
        ("/etc/hostname", &[("/etc/hostname", "/etc/hostname", Path)]),
        (
            "edit ~/.ssh/config.",
            &[("~/.ssh/config", "~/.ssh/config", Path)],
        ),
        ("./build.sh --x", &[("./build.sh", "./build.sh", Path)]),
        ("../a/b.txt:12", &[("../a/b.txt", "../a/b.txt", Path)]),
        ("src/main.rs:10:5", &[("src/main.rs", "src/main.rs", Path)]),
        (
            "/home/me/My Documents",
            &[("/home/me/My", "/home/me/My", Path)],
        ),
        ("ratio 1/2 and 2024/10/18", &[]),
        ("no links here", &[]),
        (
            "two: https://a.io and /tmp/x",
            &[
                ("https://a.io", "https://a.io", Url),
                ("/tmp/x", "/tmp/x", Path),
            ],
        ),
        ("javascript:alert(1)", &[]),
        (
            "HTTPS://Example.COM/A",
            &[("HTTPS://Example.COM/A", "HTTPS://Example.COM/A", Url)],
        ),
    ];
    for (text, want) in cases {
        let got: Vec<(String, String, LinkKind)> = detect_links(text)
            .into_iter()
            .map(|(range, uri, kind)| {
                (
                    text.chars().skip(range.start).take(range.len()).collect(),
                    uri,
                    kind,
                )
            })
            .collect();
        let want: Vec<(String, String, LinkKind)> = want
            .iter()
            .map(|(m, u, k)| ((*m).to_owned(), (*u).to_owned(), *k))
            .collect();
        assert_eq!(got, want, "{text:?}");
    }
}

#[test]
fn ranges_are_columns_even_after_wide_text() {
    let found = detect_links("é → https://a.io");
    assert_eq!(found[0].0, 4..16);
}

#[test]
fn osc8_hyperlinks_win_over_their_text_and_span_their_cells() {
    let mut term = TermHandle::new(40, 3, 10, WORD_SEPARATORS);
    term.feed(b"go \x1b]8;;https://example.org\x1b\\click me\x1b]8;;\x1b\\ https://shown.io");
    let snap = term.snapshot();
    let link = link_at(&snap, 5, 0).unwrap();
    assert_eq!(link.uri, "https://example.org", "the target, not the text");
    assert_eq!(
        (link.kind, link.start, link.end),
        (LinkKind::Hyperlink, 3, 11)
    );
    let plain = link_at(&snap, 15, 0).unwrap();
    assert_eq!(
        (plain.uri.as_str(), plain.kind),
        ("https://shown.io", LinkKind::Url)
    );
    assert!(link_at(&snap, 1, 0).is_none());
    assert!(link_at(&snap, 1, 2).is_none(), "empty row");
}
