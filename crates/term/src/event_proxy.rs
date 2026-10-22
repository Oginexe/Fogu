//! `EventProxy`: the single place where terminal output can provoke replies or reach the clipboard.
//!
//! Policy: one `match` over `alacritty_terminal::event::Event`. Terminal output is attacker input.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::term::ClipboardType;
use alacritty_terminal::term::color::COUNT;
use alacritty_terminal::vte::ansi::Rgb;

/// Maximum title length in chars after sanitizing.
pub const TITLE_MAX_CHARS: usize = 256;
/// Maximum OSC 52 clipboard-store payload in bytes; larger requests are dropped.
pub const CLIPBOARD_STORE_MAX_BYTES: usize = 1024 * 1024;

/// Full palette answered to OSC 4/10/11/12 color queries, indexed like alacritty's `Colors`
/// (0..256 indexed colors, then `NamedColor::Foreground` = 256 and the other named colors).
pub type Palette = [Rgb; COUNT];

/// Terminal event for the session/UI, drained with `TermHandle::drain_events`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TermEvent {
    /// Sanitized window title (no control chars, at most [`TITLE_MAX_CHARS`] chars).
    Title(String),
    /// Reset to the default title.
    ResetTitle,
    /// Terminal bell.
    Bell,
    /// Bytes to write back to the PTY/transport (fixed-format replies: DA, DSR, color, size).
    PtyWrite(Vec<u8>),
    /// OSC 52 write request; the UI applies the ask/allow/deny policy.
    ClipboardStore {
        /// Clipboard (`c`) or primary selection (`p`/`s`).
        target: ClipboardType,
        /// Decoded UTF-8 text the remote wants to store.
        payload: String,
        /// Payload length in bytes (for the "remote set clipboard (N bytes)" toast).
        len: usize,
    },
    /// Cursor blinking mode changed.
    CursorBlinkingChange,
}

/// State shared between the `TermHandle` and the `EventProxy` living inside `Term`.
#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) events: Vec<TermEvent>,
    pub(crate) palette: Box<Palette>,
    pub(crate) window_size: WindowSize,
}

/// Locks the shared state, recovering from poisoning (the data stays consistent: plain pushes).
pub(crate) fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `EventListener` handed to `Term`; maps alacritty events to [`TermEvent`]s.
#[derive(Clone, Debug)]
pub struct EventProxy {
    shared: Arc<Mutex<Shared>>,
    dirty: Arc<AtomicBool>,
}

impl EventProxy {
    pub(crate) fn new(shared: Arc<Mutex<Shared>>, dirty: Arc<AtomicBool>) -> Self {
        Self { shared, dirty }
    }

    fn push(&self, event: TermEvent) {
        lock(&self.shared).events.push(event);
    }
}

impl EventListener for EventProxy {
    fn send_event(&self, event: Event) {
        match event {
            Event::Title(title) => self.push(TermEvent::Title(sanitize_title(&title))),
            Event::ResetTitle => self.push(TermEvent::ResetTitle),
            Event::Bell => self.push(TermEvent::Bell),
            Event::PtyWrite(text) => self.push(TermEvent::PtyWrite(text.into_bytes())),
            Event::ClipboardStore(target, payload) => {
                let len = payload.len();
                if len <= CLIPBOARD_STORE_MAX_BYTES {
                    self.push(TermEvent::ClipboardStore {
                        target,
                        payload,
                        len,
                    });
                }
            }
            Event::ColorRequest(index, format) => {
                let mut shared = lock(&self.shared);
                if let Some(rgb) = shared.palette.get(index).copied() {
                    shared
                        .events
                        .push(TermEvent::PtyWrite(format(rgb).into_bytes()));
                }
            }
            Event::TextAreaSizeRequest(format) => {
                let mut shared = lock(&self.shared);
                let reply = format(shared.window_size).into_bytes();
                shared.events.push(TermEvent::PtyWrite(reply));
            }
            Event::CursorBlinkingChange => self.push(TermEvent::CursorBlinkingChange),
            Event::Wakeup => self.dirty.store(true, Ordering::Release),
            // OSC 52 read (`ClipboardLoad`): always denied, the formatter is never called.
            Event::ClipboardLoad(..)
            | Event::MouseCursorDirty
            | Event::Exit
            | Event::ChildExit(_) => {}
        }
    }
}

/// [`sanitize_remote`] for a window title, capped at [`TITLE_MAX_CHARS`].
pub fn sanitize_title(title: &str) -> String {
    sanitize_remote(title, TITLE_MAX_CHARS, false)
}

/// Makes server-supplied text safe to show: drops control characters (C0 except `\n` when
/// `keep_newlines`, DEL, C1) and bidi overrides/isolates (U+202A–202E, U+2066–2069, which can
/// make a prompt read differently than it is), then caps it at `max_chars`.
#[must_use]
pub fn sanitize_remote(text: &str, max_chars: usize, keep_newlines: bool) -> String {
    text.chars()
        .filter(|&c| (keep_newlines && c == '\n') || !c.is_control())
        .filter(|c| !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        .take(max_chars)
        .collect()
}

/// The "dim" variant of `c` (2/3 brightness), used for `Dim*` named colours.
pub fn dim(c: Rgb) -> Rgb {
    Rgb {
        r: c.r / 3 * 2,
        g: c.g / 3 * 2,
        b: c.b / 3 * 2,
    }
}

/// xterm-like default palette; the UI replaces it with the active color scheme.
pub fn default_palette() -> Box<Palette> {
    const ANSI: [(u8, u8, u8); 16] = [
        (0x00, 0x00, 0x00),
        (0xcd, 0x00, 0x00),
        (0x00, 0xcd, 0x00),
        (0xcd, 0xcd, 0x00),
        (0x00, 0x00, 0xee),
        (0xcd, 0x00, 0xcd),
        (0x00, 0xcd, 0xcd),
        (0xe5, 0xe5, 0xe5),
        (0x7f, 0x7f, 0x7f),
        (0xff, 0x00, 0x00),
        (0x00, 0xff, 0x00),
        (0xff, 0xff, 0x00),
        (0x5c, 0x5c, 0xff),
        (0xff, 0x00, 0xff),
        (0x00, 0xff, 0xff),
        (0xff, 0xff, 0xff),
    ];
    const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let rgb = |(r, g, b): (u8, u8, u8)| Rgb { r, g, b };

    let mut palette = Box::new([Rgb::default(); COUNT]);
    for (i, slot) in palette.iter_mut().enumerate() {
        *slot = match i {
            0..16 => ANSI.get(i).copied().map_or_else(Rgb::default, rgb),
            16..232 => {
                let n = i - 16;
                let at = |k: usize| CUBE.get(k % 6).copied().unwrap_or_default();
                Rgb {
                    r: at(n / 36),
                    g: at(n / 6),
                    b: at(n),
                }
            }
            232..256 => {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "i is in 232..256, so at most 23"
                )]
                let v = 8 + 10 * (i - 232) as u8;
                Rgb { r: v, g: v, b: v }
            }
            // Foreground, BrightForeground.
            256 | 258 | 267 => rgb((0xe5, 0xe5, 0xe5)),
            257 => Rgb::default(),
            // DimBlack..=DimWhite.
            259..267 => ANSI
                .get(i - 259)
                .copied()
                .map_or_else(Rgb::default, |c| dim(rgb(c))),
            // DimForeground.
            _ => dim(rgb((0xe5, 0xe5, 0xe5))),
        };
    }
    palette
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_lose_controls_and_bidi_overrides() {
        // RLO would show `exe.gol` as `log.exe` in the tab bar.
        assert_eq!(sanitize_title("\u{202e}exe.gol\u{7}"), "exe.gol");
        assert_eq!(sanitize_title("a\u{2066}b\u{2069}"), "ab");
    }

    fn proxy() -> (EventProxy, Arc<Mutex<Shared>>) {
        let shared = Arc::new(Mutex::new(Shared {
            events: Vec::new(),
            palette: default_palette(),
            window_size: WindowSize {
                num_lines: 24,
                num_cols: 80,
                cell_width: 9,
                cell_height: 18,
            },
        }));
        (
            EventProxy::new(Arc::clone(&shared), Arc::new(AtomicBool::new(false))),
            shared,
        )
    }

    #[test]
    fn clipboard_load_is_dropped_and_formatter_never_called() {
        let (proxy, shared) = proxy();
        let called = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&called);
        proxy.send_event(Event::ClipboardLoad(
            ClipboardType::Clipboard,
            Arc::new(move |_| {
                flag.store(true, Ordering::SeqCst);
                String::from("leak")
            }),
        ));
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(lock(&shared).events, Vec::new());
    }

    #[test]
    fn clipboard_store_over_cap_is_dropped() {
        let (proxy, shared) = proxy();
        let big = "x".repeat(CLIPBOARD_STORE_MAX_BYTES + 1);
        proxy.send_event(Event::ClipboardStore(ClipboardType::Clipboard, big));
        assert_eq!(lock(&shared).events, Vec::new());
    }

    #[test]
    fn color_request_out_of_range_is_ignored() {
        let (proxy, shared) = proxy();
        proxy.send_event(Event::ColorRequest(COUNT, Arc::new(|_| String::from("x"))));
        assert_eq!(lock(&shared).events, Vec::new());
    }

    #[test]
    fn default_palette_matches_xterm() {
        let p = default_palette();
        assert_eq!(
            p.get(1).copied(),
            Some(Rgb {
                r: 0xcd,
                g: 0,
                b: 0
            })
        );
        assert_eq!(p.get(196).copied(), Some(Rgb { r: 255, g: 0, b: 0 }));
        assert_eq!(
            p.get(255).copied(),
            Some(Rgb {
                r: 238,
                g: 238,
                b: 238
            })
        );
    }
}
