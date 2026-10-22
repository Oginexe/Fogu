//! `RenderSnapshot`: an owned copy of the visible rows, taken under a short lock and drawn
//! without holding the `Term` lock.

use alacritty_terminal::Term;
use alacritty_terminal::event::EventListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::selection::SelectionRange;
use alacritty_terminal::term::TermMode;
use alacritty_terminal::term::cell::{Flags, Hyperlink};
use alacritty_terminal::vte::ansi::{Color, CursorShape};

/// Cell attribute flags (bold/dim/italic/inverse/hidden/strikeout, underline kinds, wide-char and
/// spacer flags); alacritty's own bitflags.
pub type CellFlags = Flags;

/// One visible cell. Colors keep alacritty's `Color` semantics (named/indexed/spec); palette
/// resolution happens in the UI with the active scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    /// Base character (a space for empty cells and wide-char spacers).
    pub ch: char,
    /// Combining characters attached to `ch`.
    pub zerowidth: Option<Box<[char]>>,
    /// Foreground color.
    pub fg: Color,
    /// Background color.
    pub bg: Color,
    /// Underline color (SGR 58); `None` means "use `fg`".
    pub underline_color: Option<Color>,
    /// Attribute flags.
    pub flags: CellFlags,
    /// OSC 8 hyperlink (its target is shown on hover, never trusted from the text).
    pub hyperlink: Option<Hyperlink>,
}

/// Cursor position (viewport coordinates) and look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// Column, 0-based.
    pub col: usize,
    /// Viewport row, 0-based.
    pub row: usize,
    /// Shape requested by the app (DECSCUSR) or the default.
    pub shape: CursorShape,
    /// False when hidden (DECTCEM off) or scrolled out of the viewport.
    pub visible: bool,
}

/// Everything the UI needs to draw one frame of a terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderSnapshot {
    /// Number of columns.
    pub cols: usize,
    /// Number of visible rows.
    pub rows: usize,
    /// `rows * cols` cells, row-major, top row first.
    pub cells: Vec<Cell>,
    /// Cursor state.
    pub cursor: Cursor,
    /// How many lines the viewport is scrolled back into history (0 = bottom).
    pub display_offset: usize,
    /// Lines currently stored in scrollback history.
    pub history_len: usize,
    /// Active selection in grid coordinates (see [`selection_spans`](Self::selection_spans)).
    pub selection: Option<SelectionRange>,
    /// Terminal modes at snapshot time.
    pub mode: TermMode,
}

impl RenderSnapshot {
    /// Copies the visible rows of `term` into `cells` (cleared first, its allocation reused).
    /// Call with the lock held, then drop the lock.
    pub(crate) fn capture<T: EventListener>(term: &Term<T>, mut cells: Vec<Cell>) -> Self {
        let content = term.renderable_content();
        let cols = term.columns();
        let rows = term.screen_lines();
        let display_offset = content.display_offset;

        cells.clear();
        cells.extend(content.display_iter.map(|indexed| {
            let cell = indexed.cell;
            Cell {
                ch: cell.c,
                zerowidth: cell.zerowidth().map(Box::from),
                fg: cell.fg,
                bg: cell.bg,
                underline_color: cell.underline_color(),
                flags: cell.flags,
                hyperlink: cell.hyperlink(),
            }
        }));

        let point = content.cursor.point;
        // Grid line 0 is the top of the live screen; the viewport starts `display_offset` above.
        let row = usize::try_from(point.line.0)
            .ok()
            .map(|line| line + display_offset)
            .filter(|r| *r < rows);
        let cursor = Cursor {
            col: point.column.0,
            row: row.unwrap_or(0),
            shape: content.cursor.shape,
            visible: row.is_some() && content.cursor.shape != CursorShape::Hidden,
        };

        Self {
            cols,
            rows,
            cells,
            cursor,
            display_offset,
            history_len: term.grid().history_size(),
            selection: content.selection,
            mode: content.mode,
        }
    }

    /// Iterates over the visible rows.
    pub fn rows(&self) -> impl Iterator<Item = &[Cell]> {
        self.cells.chunks(self.cols.max(1))
    }

    /// Selected cells of the visible rows as `(row, first_col, last_col)`, both columns
    /// inclusive, top row first.
    pub fn selection_spans(&self) -> Vec<(usize, usize, usize)> {
        let Some(range) = self.selection else {
            return Vec::new();
        };
        let last = self.cols.saturating_sub(1);
        let (left, right) = (
            range.start.column.0.min(range.end.column.0),
            range.start.column.0.max(range.end.column.0),
        );
        let offset = i64::try_from(self.display_offset).unwrap_or(i64::MAX);
        (0..self.rows)
            .filter_map(|row| {
                let line = i64::try_from(row).ok()? - offset;
                let (start, end) = (i64::from(range.start.line.0), i64::from(range.end.line.0));
                if line < start || line > end {
                    return None;
                }
                let span = if range.is_block {
                    (left, right)
                } else {
                    let first = if line == start {
                        range.start.column.0
                    } else {
                        0
                    };
                    let end_col = if line == end {
                        range.end.column.0
                    } else {
                        last
                    };
                    (first, end_col)
                };
                Some((row, span.0.min(last), span.1.min(last)))
            })
            .collect()
    }

    /// Visible rows as plain text, one line per row, trailing spaces trimmed. Wide-char spacers
    /// are skipped so a CJK char reads as one char.
    pub fn to_text(&self) -> String {
        let spacers = CellFlags::WIDE_CHAR_SPACER | CellFlags::LEADING_WIDE_CHAR_SPACER;
        let mut out = String::new();
        for row in self.rows() {
            let mut line = String::new();
            for cell in row.iter().filter(|c| !c.flags.intersects(spacers)) {
                line.push(cell.ch);
                line.extend(cell.zerowidth.iter().flat_map(|z| z.iter()));
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }
}
