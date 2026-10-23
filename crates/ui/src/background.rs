//! Tab background images: a bounded decoder (PNG/JPEG/WebP only, checked by extension *and*
//! magic bytes, file size and dimension caps), run off the UI thread, downscaled to the window
//! and cached per path; plus the placement maths for Cover / Contain / Tile.
//! Image files are untrusted input: every failure is an error value, never a panic.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use fogu_core::Fit;
use iced::widget::image::Handle;
use iced::{Rectangle, Size};
use image::{ImageFormat, ImageReader, Limits, imageops::FilterType};

/// Largest image file read, in bytes.
pub const MAX_FILE_BYTES: u64 = 20 * 1024 * 1024;
/// Largest width or height decoded, in pixels.
pub const MAX_DIMENSION: u32 = 8192;
/// Most tiles drawn for `Tile`; smaller images are drawn larger instead (a 1×1 image must not
/// mean millions of draw calls).
const MAX_TILES: f32 = 1024.0;

/// Why an image could not be used. Shown in a toast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The extension is not png/jpg/jpeg/webp.
    UnsupportedType,
    /// The content is not what the extension says.
    WrongContent,
    /// Not a regular file (directory, device, FIFO…).
    NotAFile,
    /// Larger than [`MAX_FILE_BYTES`].
    TooLarge(u64),
    /// Wider or taller than [`MAX_DIMENSION`], or otherwise over the decoder limits.
    TooManyPixels,
    /// Reading the file failed.
    Io(String),
    /// The decoder rejected the data.
    Corrupt(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedType => f.write_str("only PNG, JPEG and WebP images are supported"),
            Self::WrongContent => f.write_str("the file content does not match its extension"),
            Self::NotAFile => f.write_str("not a regular file"),
            Self::TooLarge(len) => write!(
                f,
                "file too large ({} MB, limit {} MB)",
                len / (1024 * 1024),
                MAX_FILE_BYTES / (1024 * 1024)
            ),
            Self::TooManyPixels => write!(f, "image larger than {MAX_DIMENSION}×{MAX_DIMENSION}"),
            Self::Io(err) => write!(f, "cannot read the file: {err}"),
            Self::Corrupt(err) => write!(f, "cannot decode the image: {err}"),
        }
    }
}

/// A decoded image ready to draw.
#[derive(Clone, Debug)]
pub struct Decoded {
    pub handle: Handle,
    /// Pixel size of `handle`.
    pub size: Size<u32>,
    /// The target it was downscaled for (`None` = full size).
    pub fitted_for: Option<Size<u32>>,
}

/// Which decode of a file: downscaled to the window (Cover/Contain) or full size (Tile).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    pub path: PathBuf,
    pub full_size: bool,
}

impl Key {
    pub fn new(path: &Path, fit: Fit) -> Self {
        Self {
            path: expand_home(path),
            full_size: fit == Fit::Tile,
        }
    }
}

/// A leading `~/` becomes the home directory.
fn expand_home(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), dirs::home_dir()) {
        (Ok(rest), Some(home)) => home.join(rest),
        _ => path.to_path_buf(),
    }
}

fn expected_format(path: &Path) -> Option<ImageFormat> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "png" => Some(ImageFormat::Png),
        "jpg" | "jpeg" => Some(ImageFormat::Jpeg),
        "webp" => Some(ImageFormat::WebP),
        _ => None,
    }
}

/// Reads and decodes `path` within the limits; downscales it so it still covers `target`
/// (physical px), unless `target` is `None`. Blocking: run it off the UI thread.
pub fn decode(path: &Path, target: Option<Size<u32>>) -> Result<Decoded, LoadError> {
    let format = expected_format(path).ok_or(LoadError::UnsupportedType)?;
    let io = |err: std::io::Error| LoadError::Io(err.kind().to_string());
    // Checked before opening: opening a FIFO would block, a device could be endless.
    let meta = std::fs::metadata(path).map_err(io)?;
    if !meta.is_file() {
        return Err(LoadError::NotAFile);
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(LoadError::TooLarge(meta.len()));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(io)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    let len = bytes.len() as u64;
    if len > MAX_FILE_BYTES {
        return Err(LoadError::TooLarge(len));
    }
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(io)?;
    if reader.format() != Some(format) {
        return Err(LoadError::WrongContent);
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    reader.limits(limits);
    let image = reader.decode().map_err(|err| match err {
        image::ImageError::Limits(_) => LoadError::TooManyPixels,
        other => LoadError::Corrupt(other.to_string()),
    })?;
    let (w, h) = (image.width(), image.height());
    let scaled = target.and_then(|t| cover_size(Size::new(w, h), t));
    let image = match scaled {
        Some(s) => image.resize_exact(s.width, s.height, FilterType::Triangle),
        None => image,
    };
    let rgba = image.to_rgba8();
    let size = Size::new(rgba.width(), rgba.height());
    Ok(Decoded {
        handle: Handle::from_rgba(size.width, size.height, rgba.into_raw()),
        size,
        fitted_for: target.filter(|_| scaled.is_some()),
    })
}

/// The smallest size keeping `image`'s aspect that still covers `target`; `None` when `image`
/// is not larger than that already (never upscale).
fn cover_size(image: Size<u32>, target: Size<u32>) -> Option<Size<u32>> {
    let (w, h) = (f64::from(image.width), f64::from(image.height));
    let scale = (f64::from(target.width) / w).max(f64::from(target.height) / h);
    if scale.is_nan() || scale >= 1.0 {
        return None;
    }
    Some(Size::new(px(w * scale), px(h * scale)))
}

/// `v` rounded up to whole pixels, at least 1.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "clamped to 1..=u32::MAX first; `as` saturates"
)]
pub fn px(v: f64) -> u32 {
    v.ceil().clamp(1.0, f64::from(u32::MAX)) as u32
}

/// Where to draw an image of `image` px inside `area` for `fit` (the caller clips to `area`).
#[expect(
    clippy::cast_possible_truncation,
    reason = "u32 to f32 through f64: image sizes are far below f32 precision"
)]
pub fn placements(area: Rectangle, image: Size<u32>, fit: Fit) -> Vec<Rectangle> {
    let (iw, ih) = (
        f64::from(image.width) as f32,
        f64::from(image.height) as f32,
    );
    if iw < 1.0 || ih < 1.0 || area.width <= 0.0 || area.height <= 0.0 {
        return Vec::new();
    }
    let centred = |scale: f32| {
        let (w, h) = (iw * scale, ih * scale);
        Rectangle {
            x: area.x + (area.width - w) / 2.0,
            y: area.y + (area.height - h) / 2.0,
            width: w,
            height: h,
        }
    };
    match fit {
        Fit::Cover => vec![centred((area.width / iw).max(area.height / ih))],
        Fit::Contain => vec![centred((area.width / iw).min(area.height / ih))],
        Fit::Tile => {
            let count = (area.width / iw).ceil() * (area.height / ih).ceil();
            let grow = (count / MAX_TILES).sqrt().max(1.0);
            let (tw, th) = (iw * grow, ih * grow);
            let mut tiles = Vec::new();
            let mut y = area.y;
            while y < area.y + area.height {
                let mut x = area.x;
                while x < area.x + area.width {
                    tiles.push(Rectangle::new(iced::Point::new(x, y), Size::new(tw, th)));
                    x += tw;
                }
                y += th;
            }
            tiles
        }
    }
}

/// What a tab draws under its panes.
#[derive(Clone, Debug)]
pub enum Backdrop {
    /// A solid colour.
    Color(iced::Color),
    /// A decoded image.
    Image {
        handle: Handle,
        size: Size<u32>,
        opacity: f32,
        fit: Fit,
    },
}

impl Backdrop {
    /// Draws the backdrop over `area`, clipped to it.
    pub fn draw(&self, renderer: &mut iced::Renderer, area: Rectangle) {
        use iced::advanced::image::{Image, Renderer as _};
        use iced::advanced::renderer::{Quad, Renderer as _};
        match self {
            Self::Color(color) => {
                let quad = Quad {
                    bounds: area,
                    ..Quad::default()
                };
                renderer.fill_quad(quad, *color);
            }
            Self::Image {
                handle,
                size,
                opacity,
                fit,
            } => {
                for rect in placements(area, *size, *fit) {
                    let image = Image::new(handle.clone()).opacity(*opacity);
                    renderer.draw_image(image, rect, area);
                }
            }
        }
    }
}

/// One cached decode.
#[derive(Debug, Default)]
struct Entry {
    image: Option<Decoded>,
    loading: bool,
    failed: bool,
}

/// Decoded backgrounds by [`Key`]. Entries no tab uses are dropped.
#[derive(Debug, Default)]
pub struct Cache {
    entries: HashMap<Key, Entry>,
}

impl Cache {
    /// The image for `key`, if decoded.
    pub fn get(&self, key: &Key) -> Option<&Decoded> {
        self.entries.get(key).and_then(|e| e.image.as_ref())
    }

    /// Keys that need a (re)decode for a window of `target` physical px, marked as loading.
    /// Only `wanted` keys are kept. A failed key is not retried until [`Cache::forget`].
    pub fn missing(&mut self, wanted: &[Key], target: Size<u32>) -> Vec<Key> {
        self.entries.retain(|k, _| wanted.contains(k));
        let mut out = Vec::new();
        for key in wanted {
            let entry = self.entries.entry(key.clone()).or_default();
            if entry.loading || entry.failed {
                continue;
            }
            let stale = match &entry.image {
                None => true,
                // Downscaled for a smaller window: decode again for the bigger one.
                Some(img) => img
                    .fitted_for
                    .is_some_and(|f| target.width > f.width || target.height > f.height),
            };
            if stale {
                entry.loading = true;
                out.push(key.clone());
            }
        }
        out
    }

    /// Stores a finished decode; `false` when it failed (the caller shows the error).
    pub fn finish(&mut self, key: &Key, result: Result<Decoded, LoadError>) -> bool {
        let Some(entry) = self.entries.get_mut(key) else {
            return true; // No longer wanted.
        };
        entry.loading = false;
        if let Ok(image) = result {
            entry.image = Some(image);
            return true;
        }
        entry.failed = true;
        false
    }

    /// Drops `path`'s decodes so the next use reads the file again.
    pub fn forget(&mut self, path: &Path) {
        let path = expand_home(path);
        self.entries.retain(|k, _| k.path != path);
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("fogu-bg-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        image::RgbaImage::new(w, h)
            .write_to(&mut out, ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    #[test]
    fn decodes_a_tiny_png_and_rejects_bad_files() {
        let dir = TempDir::new("decode");
        let ok = dir.0.join("one.PNG");
        std::fs::write(&ok, png(1, 1)).unwrap();
        let img = decode(&ok, Some(Size::new(100, 100))).unwrap();
        assert_eq!(img.size, Size::new(1, 1));
        assert!(img.fitted_for.is_none(), "never upscaled");

        let text = dir.0.join("notes.png");
        std::fs::write(&text, "just some text, not an image").unwrap();
        assert_eq!(decode(&text, None).unwrap_err(), LoadError::WrongContent);

        let jpg_named_png = dir.0.join("photo.jpg");
        std::fs::write(&jpg_named_png, png(1, 1)).unwrap();
        assert_eq!(
            decode(&jpg_named_png, None).unwrap_err(),
            LoadError::WrongContent
        );

        let gif = dir.0.join("anim.gif");
        std::fs::write(&gif, b"GIF89a").unwrap();
        assert_eq!(decode(&gif, None).unwrap_err(), LoadError::UnsupportedType);

        let huge = dir.0.join("huge.png");
        let file = std::fs::File::create(&huge).unwrap();
        file.set_len(MAX_FILE_BYTES + 1).unwrap(); // Sparse: no real disk use.
        assert!(matches!(decode(&huge, None), Err(LoadError::TooLarge(_))));

        let wide = dir.0.join("wide.png");
        std::fs::write(&wide, png(MAX_DIMENSION + 1, 1)).unwrap();
        assert_eq!(decode(&wide, None).unwrap_err(), LoadError::TooManyPixels);

        let mut cut = png(64, 64);
        cut.truncate(cut.len() / 2);
        let corrupt = dir.0.join("cut.png");
        std::fs::write(&corrupt, cut).unwrap();
        assert!(matches!(decode(&corrupt, None), Err(LoadError::Corrupt(_))));

        let missing = decode(&dir.0.join("missing.png"), None);
        assert!(matches!(missing, Err(LoadError::Io(_))));
        let folder = dir.0.join("folder.png");
        std::fs::create_dir_all(&folder).unwrap();
        assert_eq!(decode(&folder, None).unwrap_err(), LoadError::NotAFile);
    }

    #[test]
    fn downscales_to_cover_the_window() {
        let dir = TempDir::new("scale");
        let path = dir.0.join("big.png");
        std::fs::write(&path, png(400, 200)).unwrap();
        let img = decode(&path, Some(Size::new(100, 100))).unwrap();
        assert_eq!(img.size, Size::new(200, 100));
        assert_eq!(img.fitted_for, Some(Size::new(100, 100)));
        assert_eq!(decode(&path, None).unwrap().size, Size::new(400, 200));
    }

    #[test]
    fn placements_per_fit() {
        let area = Rectangle::new(iced::Point::ORIGIN, Size::new(200.0, 100.0));
        let cover = placements(area, Size::new(100, 100), Fit::Cover);
        assert_eq!(
            cover,
            [Rectangle::new(
                iced::Point::new(0.0, -50.0),
                Size::new(200.0, 200.0)
            )]
        );
        let contain = placements(area, Size::new(100, 100), Fit::Contain);
        assert_eq!(
            contain,
            [Rectangle::new(
                iced::Point::new(50.0, 0.0),
                Size::new(100.0, 100.0)
            )]
        );
        assert_eq!(placements(area, Size::new(60, 60), Fit::Tile).len(), 4 * 2);
        // A 1×1 image is not drawn 20 000 times.
        assert!(placements(area, Size::new(1, 1), Fit::Tile).len() <= 1100);
        assert_eq!(placements(area, Size::new(0, 5), Fit::Cover), []);
    }

    #[test]
    fn cache_requests_once_and_drops_unused_keys() {
        let mut cache = Cache::default();
        let a = Key::new(Path::new("/a.png"), Fit::Cover);
        let window = Size::new(100, 100);
        assert_eq!(cache.missing(std::slice::from_ref(&a), window).len(), 1);
        assert!(
            cache.missing(std::slice::from_ref(&a), window).is_empty(),
            "in flight"
        );
        assert!(!cache.finish(&a, Err(LoadError::NotAFile)));
        assert!(
            cache.missing(std::slice::from_ref(&a), window).is_empty(),
            "failed: no retry"
        );
        cache.forget(Path::new("/a.png"));
        assert_eq!(cache.missing(std::slice::from_ref(&a), window).len(), 1);
        let img = Decoded {
            handle: Handle::from_rgba(1, 1, vec![0; 4]),
            size: Size::new(1, 1),
            fitted_for: Some(window),
        };
        assert!(cache.finish(&a, Ok(img)));
        assert!(cache.get(&a).is_some());
        let bigger = Size::new(200, 100);
        assert_eq!(
            cache.missing(std::slice::from_ref(&a), bigger).len(),
            1,
            "window grew"
        );
        assert_eq!(cache.missing(&[], window).len(), 0);
        assert!(cache.get(&a).is_none(), "unused entries are dropped");
    }
}
