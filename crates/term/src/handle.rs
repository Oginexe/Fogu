//! `TermHandle`: sync terminal core. Feed bytes in, take snapshots and drained events out.
//! No async, no PTY: the read loop lives in `fogu-session`.

use std::fmt;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use alacritty_terminal::Term;
use alacritty_terminal::event::WindowSize;
use alacritty_terminal::grid::{Cursor as GridCursor, Dimensions, Grid, Scroll};
use alacritty_terminal::index::{Boundary, Direction, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::sync::FairMutex;
use alacritty_terminal::term::color::COUNT;
use alacritty_terminal::term::search::RegexSearch;
use alacritty_terminal::term::{Config, MIN_COLUMNS, TermMode};
use alacritty_terminal::vte::ansi::{ClearMode, CursorShape, Handler as _, Processor};

use crate::event_proxy::{
    EventProxy, Palette, Shared, TermEvent, default_palette, lock, sanitize_title,
};
use crate::snapshot::RenderSnapshot;

/// Maximum bytes parsed per `Term` lock, so the renderer can always grab it within a frame.
const MAX_BYTES_PER_LOCK: usize = 64 * 1024;

/// The default word separators: the characters that end a double-click (semantic) selection.
pub const WORD_SEPARATORS: &str = " ()[]{}'\"";

/// Grid size in cells.
#[derive(Clone, Copy, Debug)]
struct Size {
    cols: usize,
    rows: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.rows
    }

    fn screen_lines(&self) -> usize {
        self.rows
    }

    fn columns(&self) -> usize {
        self.cols
    }
}

/// One terminal: `alacritty_terminal::Term` behind a `FairMutex`, plus the VT parser that the
/// feeding side (session task) owns.
pub struct TermHandle {
    term: Arc<FairMutex<Term<EventProxy>>>,
    processor: Processor,
    shared: Arc<Mutex<Shared>>,
    dirty: Arc<AtomicBool>,
    /// The options `Term` was built with (kept to change one of them later).
    config: Config,
}

impl fmt::Debug for TermHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size = lock(&self.shared).window_size;
        f.debug_struct("TermHandle")
            .field("cols", &size.num_cols)
            .field("rows", &size.num_lines)
            .finish_non_exhaustive()
    }
}

// alacritty's reflow never terminates at 1 column once a wide char is on screen
#[expect(
    clippy::cast_possible_truncation,
    reason = "alacritty's MIN_COLUMNS is 2"
)]
const MIN_COLS: u16 = MIN_COLUMNS as u16;

impl TermHandle {
    /// Creates a terminal of `cols` x `rows` cells (at least 2 x 1) keeping `scrollback_lines`
    /// lines of history. `word_separators` ends a double-click (semantic) selection
    /// (`Config.terminal.word_separators`); pass [`WORD_SEPARATORS`] for the default.
    pub fn new(cols: u16, rows: u16, scrollback_lines: usize, word_separators: &str) -> Self {
        let (cols, rows) = (cols.max(MIN_COLS), rows.max(1));
        let shared = Arc::new(Mutex::new(Shared {
            events: Vec::new(),
            palette: default_palette(),
            window_size: WindowSize {
                num_lines: rows,
                num_cols: cols,
                cell_width: 0,
                cell_height: 0,
            },
        }));
        let dirty = Arc::new(AtomicBool::new(false));
        let proxy = EventProxy::new(Arc::clone(&shared), Arc::clone(&dirty));
        // OSC 52 read is also disabled here (`OnlyCopy`); the proxy drops it regardless.
        let config = Config {
            scrolling_history: scrollback_lines,
            semantic_escape_chars: word_separators.to_owned(),
            ..Config::default()
        };
        let size = Size {
            cols: cols.into(),
            rows: rows.into(),
        };
        let term = Term::new(config.clone(), &size, proxy);
        Self {
            term: Arc::new(FairMutex::new(term)),
            processor: Processor::new(),
            shared,
            dirty,
            config,
        }
    }

    /// A second handle onto the same terminal (grid, events, palette, `dirty`) with its own idle
    /// parser: the session task feeds one handle, the UI snapshots/resizes the other. Only the
    /// feeding handle may call [`feed`](Self::feed) and [`drain_events`](Self::drain_events).
    #[must_use]
    pub fn share(&self) -> Self {
        Self {
            term: Arc::clone(&self.term),
            processor: Processor::new(),
            shared: Arc::clone(&self.shared),
            dirty: Arc::clone(&self.dirty),
            config: self.config.clone(),
        }
    }

    /// Parses `bytes`, locking the `Term` once per chunk of at most 64 KiB. `feed(&[])` flushes a
    /// synchronized update (DEC 2026) whose [`sync_timeout`](Self::sync_timeout) has passed.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self
            .processor
            .sync_timeout()
            .sync_timeout()
            .is_some_and(|t| t <= Instant::now())
        {
            self.processor.stop_sync(&mut *self.term.lock());
        }
        for chunk in bytes.chunks(MAX_BYTES_PER_LOCK) {
            self.processor.advance(&mut *self.term.lock(), chunk);
        }
    }

    /// Deadline of a pending synchronized update; call `feed(&[])` once it passes.
    pub fn sync_timeout(&self) -> Option<Instant> {
        self.processor.sync_timeout().sync_timeout()
    }

    /// Resizes (and reflows) the grid to `cols` x `rows` cells, at least 2 x 1.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        let (cols, rows) = (cols.max(MIN_COLS), rows.max(1));
        self.term.lock().resize(Size {
            cols: cols.into(),
            rows: rows.into(),
        });
        let mut shared = lock(&self.shared);
        shared.window_size.num_cols = cols;
        shared.window_size.num_lines = rows;
    }

    /// Sets the cell size in pixels, used to answer `CSI 14 t` text-area size queries.
    pub fn set_cell_size_px(&mut self, width: u16, height: u16) {
        let mut shared = lock(&self.shared);
        shared.window_size.cell_width = width;
        shared.window_size.cell_height = height;
    }

    /// Replaces the palette used to answer OSC 4/10/11/12 color queries.
    pub fn set_palette(&mut self, palette: Box<Palette>) {
        lock(&self.shared).palette = palette;
    }

    /// Sets the cursor shape used until the application picks one with DECSCUSR
    /// (`Config.appearance.cursor_shape`).
    pub fn set_default_cursor_shape(&mut self, shape: CursorShape) {
        self.config.default_cursor_style.shape = shape;
        self.term.lock().set_options(self.config.clone());
    }

    /// Scrolls the viewport through history.
    pub fn scroll_display(&mut self, scroll: Scroll) {
        self.term.lock().scroll_display(scroll);
    }

    /// Clears the visible screen and the scrollback history (the "Clear terminal" action),
    /// then scrolls back to the bottom.
    pub fn clear(&mut self) {
        let mut term = self.term.lock();
        term.clear_screen(ClearMode::All);
        term.clear_screen(ClearMode::Saved);
        term.scroll_display(Scroll::Bottom);
    }

    /// Prepares the grid of a session that ended for the next session (restart / reconnect
    /// keeping history, `terminal.keep_history_on_restart`). The old session was attacker
    /// input, so nothing it set may reach the new one: the alternate screen is left and its
    /// content dropped; every mode (mouse reporting, bracketed paste, application cursor keys
    /// and keypad, focus reports, origin, insert, wrap, cursor visibility), the scroll region,
    /// tab stops, charsets, SGR attributes and hyperlink, DECSCUSR cursor style, the saved
    /// cursor, title and title stack, keyboard-protocol stacks and OSC 4/10/11/12 colours go
    /// back to their defaults (what RIS resets), and undelivered events (replies, titles,
    /// OSC 52 writes) are dropped. Only the primary screen's text and the scrollback are kept,
    /// followed by `separator` on a dim line of its own. The next session must get a fresh
    /// [`share`](Self::share) (a new parser), so a half-received escape sequence or pending
    /// synchronized update of the old session can't continue either.
    pub fn reset_for_new_session(&mut self, separator: &str) {
        let column = {
            let mut term = self.term.lock();
            if term.mode().contains(TermMode::ALT_SCREEN) {
                term.swap_alt();
            }
            // RIS on a placeholder grid: resets everything but the primary screen + history.
            let blank = Grid::new(term.screen_lines(), term.columns(), 0);
            let primary = std::mem::replace(term.grid_mut(), blank);
            term.reset_state();
            *term.grid_mut() = primary;
            for index in 0..COUNT {
                term.reset_color(index);
            }
            let grid = term.grid_mut();
            // Default template (SGR, hyperlink), charsets and pending wrap; same position.
            grid.cursor = GridCursor {
                point: grid.cursor.point,
                ..GridCursor::default()
            };
            grid.saved_cursor = grid.cursor.clone();
            term.scroll_display(Scroll::Bottom);
            term.grid().cursor.point.column.0
        };
        lock(&self.shared).events.clear();
        let mut line = Vec::new();
        if column > 0 {
            line.extend_from_slice(b"\r\n");
        }
        line.extend_from_slice(b"\x1b[2m");
        line.extend_from_slice(sanitize_title(separator).as_bytes());
        line.extend_from_slice(b"\x1b[0m\r\n");
        let mut parser: Processor = Processor::new();
        parser.advance(&mut *self.term.lock(), &line);
    }

    /// The last `max_lines` rows of the primary screen and its history as inert runs
    /// ([`history`](crate::history)); `now` = unix seconds stored with them.
    pub fn capture_history(&self, max_lines: usize, now: u64) -> crate::history::SavedHistory {
        crate::history::capture(&mut self.term.lock(), max_lines, now)
    }

    /// Redraws `saved` through the parser (text and SGR built from its attributes only, control
    /// characters shown as U+FFFD). Call [`validate`](crate::history::validate) first for loaded
    /// data. Undelivered events are dropped: the restored text can't produce any.
    pub fn restore_history(&mut self, saved: &crate::history::SavedHistory) {
        self.feed(&crate::history::generate(saved));
        lock(&self.shared).events.clear();
    }

    /// Starts a new selection of `kind` at grid `point` (clamped to the grid; line 0 is the top
    /// of the live screen, negative lines are history).
    pub fn start_selection(&mut self, kind: SelectionType, point: Point, side: Side) {
        let mut term = self.term.lock();
        let point = point.grid_clamp(&*term, Boundary::Grid);
        term.selection = Some(Selection::new(kind, point, side));
    }

    /// Moves the free end of the current selection to grid `point` (clamped); no-op without one.
    pub fn update_selection(&mut self, point: Point, side: Side) {
        let mut term = self.term.lock();
        let point = point.grid_clamp(&*term, Boundary::Grid);
        if let Some(selection) = term.selection.as_mut() {
            selection.update(point, side);
        }
    }

    /// Selects everything: the whole history and the screen.
    pub fn select_all(&mut self) {
        let mut term = self.term.lock();
        let top = Point::new(
            term.grid().topmost_line(),
            alacritty_terminal::index::Column(0),
        );
        let bottom = Point::new(
            term.grid().bottommost_line(),
            alacritty_terminal::index::Column(term.columns().saturating_sub(1)),
        );
        let mut selection = Selection::new(SelectionType::Simple, top, Side::Left);
        selection.update(bottom, Side::Right);
        term.selection = Some(selection);
    }

    /// Selects the next match of the plain text `query` (smart case: case-insensitive unless it
    /// has an uppercase letter) above the current selection (`up`) or below it, starting from the
    /// cursor without one and wrapping around the buffer, and scrolls it into view. `false` when
    /// nothing matches (the selection is then dropped).
    pub fn search(&mut self, query: &str, up: bool) -> bool {
        let Ok(mut regex) = RegexSearch::new(&regex::escape(query)) else {
            return false;
        };
        let mut term = self.term.lock();
        let range = term.selection.as_ref().and_then(|s| s.to_range(&*term));
        let (origin, direction, side) = match (range, up) {
            (Some(r), true) => (
                r.start.sub(&*term, Boundary::None, 1),
                Direction::Left,
                Side::Right,
            ),
            (Some(r), false) => (
                r.end.add(&*term, Boundary::None, 1),
                Direction::Right,
                Side::Left,
            ),
            (None, true) => (term.grid().cursor.point, Direction::Left, Side::Right),
            (None, false) => (term.grid().cursor.point, Direction::Right, Side::Left),
        };
        let Some(found) = term.search_next(&mut regex, origin, direction, side, None) else {
            term.selection = None;
            return false;
        };
        let mut selection = Selection::new(SelectionType::Simple, *found.start(), Side::Left);
        selection.update(*found.end(), Side::Right);
        term.selection = Some(selection);
        term.scroll_to_point(*found.start());
        true
    }

    /// Drops the current selection.
    pub fn clear_selection(&mut self) {
        self.term.lock().selection = None;
    }

    /// Selected text with trailing whitespace trimmed on every line; `None` when nothing is
    /// selected.
    pub fn selection_text(&self) -> Option<String> {
        let text = self.term.lock().selection_to_string()?;
        let trimmed = text
            .split('\n')
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n");
        (!trimmed.trim().is_empty()).then_some(trimmed)
    }

    /// Copies the visible rows under a short lock.
    pub fn snapshot(&self) -> RenderSnapshot {
        RenderSnapshot::capture(&self.term.lock(), Vec::new())
    }

    /// [`Self::snapshot`] into `cells`, the previous snapshot's buffer: no new allocation per
    /// refresh.
    pub fn snapshot_reusing(&self, cells: Vec<crate::Cell>) -> RenderSnapshot {
        RenderSnapshot::capture(&self.term.lock(), cells)
    }

    /// Takes all events produced since the last call.
    pub fn drain_events(&mut self) -> Vec<TermEvent> {
        std::mem::take(&mut lock(&self.shared).events)
    }

    /// Shared "needs redraw" flag used to coalesce wakeups between session and UI.
    pub fn dirty(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.dirty)
    }

    /// Current terminal modes (for the input encoder).
    pub fn mode(&self) -> TermMode {
        *self.term.lock().mode()
    }

    /// Visible rows as text, trailing spaces trimmed (test/debug helper).
    pub fn dump_grid(&self) -> String {
        self.snapshot().to_text()
    }
}
