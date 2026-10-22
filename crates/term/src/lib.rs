//! `fogu-term`: sync terminal core over `alacritty_terminal`.
//!
//! Feed bytes with [`TermHandle::feed`], draw from [`TermHandle::snapshot`], forward
//! [`TermHandle::drain_events`] to the session/UI. No async runtime, no GUI, no PTY.

mod event_proxy;
mod handle;
pub mod history;
pub mod input;
pub mod links;
pub mod login_script;
mod osc;
mod snapshot;

pub use alacritty_terminal::grid::Scroll;
pub use alacritty_terminal::index::{Column, Line, Point, Side};
pub use alacritty_terminal::selection::{SelectionRange, SelectionType};
pub use alacritty_terminal::term::{ClipboardType, TermMode};
pub use alacritty_terminal::vte::ansi::{Color, CursorShape, NamedColor, Rgb};
pub use event_proxy::{
    CLIPBOARD_STORE_MAX_BYTES, EventProxy, Palette, TITLE_MAX_CHARS, TermEvent, default_palette,
    dim, sanitize_remote, sanitize_title,
};
pub use handle::{TermHandle, WORD_SEPARATORS};
pub use osc::{OscEvent, OscScanner, PromptMark};
pub use snapshot::{Cell, CellFlags, Cursor, RenderSnapshot};
