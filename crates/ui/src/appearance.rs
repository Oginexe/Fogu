//! Appearance settings that need a decision: scheme lookup with a visible fallback and the
//! config -> terminal cursor mapping.

use fogu_core::{ColorScheme, config::CursorShapeCfg};
use fogu_term::CursorShape;

use crate::notifications::{Level, Notification};

/// The scheme called `name`; an unknown name falls back to the default scheme and says so.
pub fn resolve_scheme(name: &str) -> (ColorScheme, Option<Notification>) {
    if let Some(scheme) = ColorScheme::by_name(name) {
        return (scheme, None);
    }
    let note = Notification::new(Level::Warn, "Unknown colour scheme").detail(format!(
        "\"{name}\" is not a known scheme; using \"{}\"",
        ColorScheme::default().name
    ));
    (ColorScheme::default(), Some(note))
}

/// Config cursor shape as the terminal's.
pub fn cursor_shape(cfg: CursorShapeCfg) -> CursorShape {
    match cfg {
        CursorShapeCfg::Block => CursorShape::Block,
        CursorShapeCfg::Beam => CursorShape::Beam,
        CursorShapeCfg::Underline => CursorShape::Underline,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn known_scheme_resolves_silently() {
        let (scheme, note) = resolve_scheme("Dracula");
        assert_eq!(scheme.name, "Dracula");
        assert!(note.is_none());
    }

    #[test]
    fn unknown_scheme_falls_back_with_a_warning() {
        let (scheme, note) = resolve_scheme("Nope");
        assert_eq!(scheme.name, ColorScheme::default().name);
        let note = note.unwrap();
        assert_eq!(note.level, Level::Warn);
        assert!(note.detail.contains("Nope"));
    }

    #[test]
    fn cursor_shapes_map_one_to_one() {
        assert_eq!(cursor_shape(CursorShapeCfg::Beam), CursorShape::Beam);
        assert_eq!(
            cursor_shape(CursorShapeCfg::Underline),
            CursorShape::Underline
        );
        assert_eq!(cursor_shape(CursorShapeCfg::Block), CursorShape::Block);
    }
}
