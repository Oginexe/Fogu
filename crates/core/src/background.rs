//! Tab/profile backgrounds: a solid
//! colour or an image under the terminal, set per profile and overridable per tab, plus the one
//! resolve function [`effective_background`].

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::Appearance;
use crate::profile::Profile;
use crate::scheme::RgbColor;

/// Image opacity when the config does not say.
pub const DEFAULT_IMAGE_OPACITY: f32 = 0.85;
/// Alpha of the terminal's default background over an image when
/// `appearance.terminal_bg_alpha` is unset.
pub const IMAGE_TERMINAL_ALPHA: f32 = 0.75;
/// Same over a solid colour: the colour replaces the scheme background.
pub const COLOR_TERMINAL_ALPHA: f32 = 0.0;

/// How an image fills the pane area.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fit {
    /// Scaled to cover the whole area, cropped at the edges.
    #[default]
    Cover,
    /// Scaled to fit inside the area, letterboxed.
    Contain,
    /// Repeated at its own size.
    Tile,
}

/// A background drawn under a tab's panes. TOML: `background = { color = "#1E2030" }` or
/// `background = { image = { path = "/…/wall.png", opacity = 0.85, fit = "cover" } }`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Background {
    /// A solid colour.
    Color(RgbColor),
    /// A PNG/JPEG/WebP image file.
    Image {
        /// The image file (a leading `~/` means the home directory).
        path: PathBuf,
        /// 0 (invisible) ..= 1 (opaque); see [`Background::opacity`].
        #[serde(default = "default_opacity")]
        opacity: f32,
        /// How the image fills the area.
        #[serde(default)]
        fit: Fit,
        /// Accepted for config compatibility; not rendered yet.
        #[serde(default)]
        blur: bool,
    },
}

fn default_opacity() -> f32 {
    DEFAULT_IMAGE_OPACITY
}

/// `value` clamped to 0..=1; `fallback` for NaN/infinite.
fn unit(value: f32, fallback: f32) -> f32 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        fallback
    }
}

impl Background {
    /// A new image background with the default opacity and fit.
    #[must_use]
    pub fn image(path: PathBuf) -> Self {
        Self::Image {
            path,
            opacity: DEFAULT_IMAGE_OPACITY,
            fit: Fit::default(),
            blur: false,
        }
    }

    /// The image opacity clamped to 0..=1 (1 for a colour).
    #[must_use]
    pub fn opacity(&self) -> f32 {
        match self {
            Self::Color(_) => 1.0,
            Self::Image { opacity, .. } => unit(*opacity, DEFAULT_IMAGE_OPACITY),
        }
    }
}

/// A tab's own choice, which wins over its profile's background.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TabBackground {
    /// Whatever the tab's profile says.
    #[default]
    Profile,
    /// No background, even if the profile has one.
    None,
    /// This background.
    Set(Background),
}

/// The background a tab draws and how opaque the terminal's default background is over it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EffectiveBackground<'a> {
    /// What to draw under the panes.
    pub background: &'a Background,
    /// Alpha (0..=1) of cells whose background is the scheme default; explicit SGR backgrounds
    /// stay opaque.
    pub terminal_bg_alpha: f32,
}

/// Resolves tab override > profile background, and the terminal alpha:
/// `appearance.terminal_bg_alpha` when set, else 0.75 over an image and 0 over a colour.
/// `None` = no background (the terminal stays opaque).
#[must_use]
pub fn effective_background<'a>(
    tab: &'a TabBackground,
    profile: &'a Profile,
    appearance: &Appearance,
) -> Option<EffectiveBackground<'a>> {
    let background = match tab {
        TabBackground::Profile => profile.background.as_ref()?,
        TabBackground::None => return None,
        TabBackground::Set(background) => background,
    };
    let auto = match background {
        Background::Color(_) => COLOR_TERMINAL_ALPHA,
        Background::Image { .. } => IMAGE_TERMINAL_ALPHA,
    };
    let terminal_bg_alpha = appearance.terminal_bg_alpha.map_or(auto, |a| unit(a, auto));
    Some(EffectiveBackground {
        background,
        terminal_bg_alpha,
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    fn color() -> Background {
        Background::Color(RgbColor { r: 1, g: 2, b: 3 })
    }

    fn image() -> Background {
        Background::image(PathBuf::from("/wall.png"))
    }

    #[test]
    fn precedence_and_alpha_table() {
        let with = |bg: Option<Background>| Profile {
            background: bg,
            ..Profile::default_shell()
        };
        let auto = Appearance::default();
        let half = Appearance {
            terminal_bg_alpha: Some(0.5),
            ..Appearance::default()
        };
        // (tab, profile background, appearance, expected background, expected alpha)
        let rows = [
            (TabBackground::Profile, None, &auto, None, 1.0),
            (
                TabBackground::Profile,
                Some(image()),
                &auto,
                Some(image()),
                0.75,
            ),
            (
                TabBackground::Profile,
                Some(color()),
                &auto,
                Some(color()),
                0.0,
            ),
            (
                TabBackground::Profile,
                Some(image()),
                &half,
                Some(image()),
                0.5,
            ),
            (
                TabBackground::Profile,
                Some(color()),
                &half,
                Some(color()),
                0.5,
            ),
            (TabBackground::None, Some(image()), &auto, None, 1.0),
            (
                TabBackground::Set(color()),
                Some(image()),
                &auto,
                Some(color()),
                0.0,
            ),
            (TabBackground::Set(image()), None, &half, Some(image()), 0.5),
        ];
        for (tab, profile_bg, appearance, want, alpha) in rows {
            let profile = with(profile_bg);
            let got = effective_background(&tab, &profile, appearance);
            assert_eq!(got.map(|e| e.background.clone()), want, "{tab:?}");
            let got_alpha = got.map_or(1.0, |e| e.terminal_bg_alpha);
            assert!((got_alpha - alpha).abs() < f32::EPSILON, "{tab:?}");
        }
    }

    #[test]
    fn out_of_range_values_are_clamped() {
        let profile = Profile {
            background: Some(Background::Image {
                path: PathBuf::from("/a.png"),
                opacity: 7.0,
                fit: Fit::Tile,
                blur: false,
            }),
            ..Profile::default_shell()
        };
        let appearance = Appearance {
            terminal_bg_alpha: Some(f32::NAN),
            ..Appearance::default()
        };
        let got = effective_background(&TabBackground::Profile, &profile, &appearance).unwrap();
        assert!((got.background.opacity() - 1.0).abs() < f32::EPSILON);
        assert!((got.terminal_bg_alpha - IMAGE_TERMINAL_ALPHA).abs() < f32::EPSILON);
    }

    #[test]
    fn toml_forms_parse_with_defaults() {
        #[derive(Deserialize, Serialize)]
        struct Wrap {
            background: Background,
        }
        let c: Wrap = toml::from_str("background = { color = \"#010203\" }").unwrap();
        assert_eq!(c.background, color());
        let i: Wrap = toml::from_str("background = { image = { path = \"/wall.png\" } }").unwrap();
        assert_eq!(i.background, image());
        let text = toml::to_string(&i).unwrap();
        let back: Wrap = toml::from_str(&text).unwrap();
        assert_eq!(back.background, image());
        let bad = toml::from_str::<Wrap>("background = { image = { path = \"/a\", fit = \"x\" } }");
        assert!(bad.is_err());
    }
}
