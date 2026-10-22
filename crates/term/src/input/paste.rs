//! Paste sanitising and bracketing: the single security boundary between clipboard text and the
//! PTY (paste injection).
//!
//! Rather than forwarding the clipboard verbatim between `ESC[200~`/`ESC[201~` markers,
//! [`encode_paste`] strips any embedded end-of-paste marker (and, as a stronger blanket rule, every
//! raw `ESC` byte and every C1 control) so pasted text can never break out of bracketed paste and masquerade as a
//! second, attacker-controlled command line.

/// Options for [`encode_paste`], resolved by the caller (the UI reads `bracketed_requested` off
/// the pane's `TermMode`; the other two are config).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasteOpts {
    /// The app asked for bracketed paste (`TermMode::BRACKETED_PASTE`).
    pub bracketed_requested: bool,
    /// Trim whitespace around the pasted text.
    pub trim_whitespace: bool,
    /// Replace newlines with spaces.
    pub newlines_to_spaces: bool,
}

/// Why the UI should ask before sending a paste: how many lines it spans and its size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasteWarning {
    /// Number of lines (1 for a single line with no line break).
    pub lines: usize,
    /// Size in bytes (UTF-8).
    pub bytes: usize,
}

/// A paste over this size asks for confirmation even without a line break.
const LARGE_PASTE_BYTES: usize = 64 * 1024;
/// The bracketed-paste end marker; embedding it in pasted text must never close the real one.
const PASTE_END: &str = "\x1b[201~";

/// Whether the UI should confirm `text` before sending it: more than one line, or over
/// [`LARGE_PASTE_BYTES`]. `None` means send it straight away.
#[must_use]
pub fn needs_confirmation(text: &str) -> Option<PasteWarning> {
    let lines = normalize_newlines(text).matches('\n').count() + 1;
    let bytes = text.len();
    (lines > 1 || bytes > LARGE_PASTE_BYTES).then_some(PasteWarning { lines, bytes })
}

/// Sanitises and (optionally) brackets `text` for the PTY.
///
/// Order: normalise line endings to `\n`; strip the literal end-of-paste marker, every `ESC`
/// and every C1 control (U+0080..U+009F, whose U+009B is an 8-bit CSI) unconditionally; when bracketed paste was *not* requested, also strip the other C0
/// controls (bracketed paste tells the app to treat the payload as literal text, so those pass
/// through only in that mode); apply `newlines_to_spaces` then `trim_whitespace`; turn the
/// remaining `\n` into `\r` (what a real Enter key sends); wrap in `ESC[200~ … ESC[201~` when
/// bracketed paste was requested.
#[must_use]
pub fn encode_paste(text: &str, opts: PasteOpts) -> Vec<u8> {
    let mut s = normalize_newlines(text).replace(PASTE_END, "");
    s.retain(|c| c != '\u{1b}' && !is_c1(c) && (opts.bracketed_requested || !is_stripped_c0(c)));
    if opts.newlines_to_spaces {
        s = s.replace('\n', " ");
    }
    if opts.trim_whitespace {
        s = trim_paste(&s);
    }
    let body = s.replace('\n', "\r");
    if !opts.bracketed_requested {
        return body.into_bytes();
    }
    let mut out = Vec::with_capacity(body.len() + 12);
    out.extend_from_slice(b"\x1b[200~");
    out.extend_from_slice(body.as_bytes());
    out.extend_from_slice(b"\x1b[201~");
    out
}

/// `\r\n` and lone `\r` both become `\n`.
fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// A C1 control: never text, and U+009B/U+009D act as CSI/OSC for apps that read 8-bit
/// controls, so `\u{9b}201~` could end a bracketed paste like `ESC[201~`.
fn is_c1(c: char) -> bool {
    ('\u{80}'..='\u{9f}').contains(&c)
}

/// A C0 control (`0x00..=0x1f`) other than tab/newline/CR.
fn is_stripped_c0(c: char) -> bool {
    (c as u32) <= 0x1f && !matches!(c, '\t' | '\n' | '\r')
}

/// Whitespace trimming: a single trailing newline (no other line break) is dropped
/// outright (it is almost always a copy artefact, not an instruction to press Enter); otherwise
/// trailing whitespace is trimmed, and leading whitespace too when no line break remains.
fn trim_paste(s: &str) -> String {
    if let Some(body) = s.strip_suffix('\n')
        && !body.contains('\n')
    {
        return body.to_owned();
    }
    let trimmed = s.trim_end();
    if trimmed.contains('\n') {
        trimmed.to_owned()
    } else {
        trimmed.trim_start().to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BRACKETED: PasteOpts = PasteOpts {
        bracketed_requested: true,
        trim_whitespace: false,
        newlines_to_spaces: false,
    };
    const LEGACY: PasteOpts = PasteOpts {
        bracketed_requested: false,
        trim_whitespace: false,
        newlines_to_spaces: false,
    };

    #[test]
    fn paste_table_sanitizing() {
        let cases: &[(&str, &str, PasteOpts, &[u8])] = &[
            (
                "plain text, bracketed",
                "ls -la",
                BRACKETED,
                b"\x1b[200~ls -la\x1b[201~",
            ),
            ("plain text, legacy", "ls -la", LEGACY, b"ls -la"),
            ("empty, bracketed", "", BRACKETED, b"\x1b[200~\x1b[201~"),
            ("empty, legacy", "", LEGACY, b""),
            (
                "multi-line, bracketed: \\n -> \\r inside the wrapper",
                "one\ntwo\nthree",
                BRACKETED,
                b"\x1b[200~one\rtwo\rthree\x1b[201~",
            ),
            (
                "multi-line, legacy: \\n -> \\r, no wrapper",
                "one\ntwo",
                LEGACY,
                b"one\rtwo",
            ),
            (
                "CRLF normalises to a single \\r per line",
                "one\r\ntwo",
                BRACKETED,
                b"\x1b[200~one\rtwo\x1b[201~",
            ),
            (
                "lone CR normalises like \\n",
                "one\rtwo",
                BRACKETED,
                b"\x1b[200~one\rtwo\x1b[201~",
            ),
            (
                "embedded end marker is stripped, bracketed",
                "ls\x1b[201~\nrm -rf x",
                BRACKETED,
                b"\x1b[200~ls\rrm -rf x\x1b[201~",
            ),
            (
                "embedded end marker is stripped, legacy",
                "ls\x1b[201~\nrm -rf x",
                LEGACY,
                b"ls\rrm -rf x",
            ),
            (
                "corpus payload: fake end+start markers never break out",
                "ls\x1b[201~\nrm -rf x\x1b[200~",
                BRACKETED,
                b"\x1b[200~ls\rrm -rf x[200~\x1b[201~",
            ),
            (
                "bare ESC is always stripped, bracketed",
                "a\x1bb",
                BRACKETED,
                b"\x1b[200~ab\x1b[201~",
            ),
            (
                "bare ESC is always stripped, legacy",
                "a\x1bb",
                LEGACY,
                b"ab",
            ),
            (
                "other C0 (bell) stripped when legacy",
                "a\x07b",
                LEGACY,
                b"ab",
            ),
            (
                "other C0 (bell) passes through when bracketed",
                "a\x07b",
                BRACKETED,
                b"\x1b[200~a\x07b\x1b[201~",
            ),
            ("tab survives either mode", "a\tb", LEGACY, b"a\tb"),
            (
                "8-bit CSI (U+009B) can't end the paste either",
                "ls\u{9b}201~\nrm -rf x",
                BRACKETED,
                b"\x1b[200~ls201~\rrm -rf x\x1b[201~",
            ),
            (
                "every C1 (U+0080..U+009F) is stripped, legacy too",
                "a\u{80}\u{9d}b\u{9f}c",
                LEGACY,
                b"abc",
            ),
            (
                "text past C1 is kept",
                "caf\u{e9}",
                LEGACY,
                "caf\u{e9}".as_bytes(),
            ),
        ];
        for (name, input, opts, want) in cases {
            assert_eq!(encode_paste(input, *opts), *want, "{name}");
        }
    }

    #[test]
    fn paste_table_trim_and_newline_options() {
        let cases: &[(&str, &str, PasteOpts, &[u8])] = &[
            (
                "newlines_to_spaces joins lines before trimming",
                "one\ntwo\n",
                PasteOpts {
                    bracketed_requested: false,
                    trim_whitespace: false,
                    newlines_to_spaces: true,
                },
                b"one two ",
            ),
            (
                "trim_whitespace drops a lone trailing newline",
                "one line\n",
                PasteOpts {
                    bracketed_requested: false,
                    trim_whitespace: true,
                    newlines_to_spaces: false,
                },
                b"one line",
            ),
            (
                "trim_whitespace on multi-line trims trailing but keeps leading",
                "  one\ntwo  \n",
                PasteOpts {
                    bracketed_requested: false,
                    trim_whitespace: true,
                    newlines_to_spaces: false,
                },
                b"  one\rtwo",
            ),
        ];
        for (name, input, opts, want) in cases {
            assert_eq!(encode_paste(input, *opts), *want, "{name}");
        }
    }

    #[test]
    fn confirmation_triggers_on_multiline_or_size() {
        assert_eq!(needs_confirmation("one line"), None);
        assert_eq!(needs_confirmation(""), None);
        assert_eq!(
            needs_confirmation("one\ntwo"),
            Some(PasteWarning { lines: 2, bytes: 7 })
        );
        assert_eq!(
            needs_confirmation("one\r\ntwo\r\nthree"),
            Some(PasteWarning {
                lines: 3,
                bytes: 15
            })
        );
        let huge = "a".repeat(LARGE_PASTE_BYTES + 1);
        assert_eq!(
            needs_confirmation(&huge),
            Some(PasteWarning {
                lines: 1,
                bytes: LARGE_PASTE_BYTES + 1
            })
        );
        let exactly_max = "a".repeat(LARGE_PASTE_BYTES);
        assert_eq!(needs_confirmation(&exactly_max), None);
    }
}
