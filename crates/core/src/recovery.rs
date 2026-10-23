//! Tab recovery state: `session.toml` (tabs, layouts, which profile each pane runs) and one
//! `scrollback/<key>.json` (local) or encrypted `<key>.enc` (SSH) per pane in
//! `$XDG_STATE_HOME/fogu/`, directory `0700`, files `0600`, written atomically through
//! [`fsutil`](crate::fsutil).

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::background::TabBackground;
use crate::fsutil;
use crate::profile::{Profile, ProfileId};
use crate::scheme::RgbColor;
use crate::split::SplitTree;

/// Layout file inside the state directory.
pub const SESSION_FILE: &str = "session.toml";
/// Where a rejected layout file is kept for inspection.
pub const CORRUPT_FILE: &str = "session.toml.corrupt";
/// Scrollback directory inside the state directory.
pub const SCROLLBACK_DIR: &str = "scrollback";
/// Format version written by this build.
pub const VERSION: u32 = 1;
/// A layout file larger than this is refused.
pub const MAX_SESSION_BYTES: u64 = 1024 * 1024;
/// Hard cap on all scrollback files together; the oldest go first.
pub const MAX_TOTAL_SCROLLBACK: u64 = 32 * 1024 * 1024;
/// The privacy note shown before clearing and above `[recovery]`.
pub const PRIVACY_NOTE: &str = "Saved local scrollback may contain passwords or other secrets \
                                shown in the terminal. It is stored unencrypted, readable only by \
                                your user. Saved SSH scrollback is encrypted.";

/// Everything needed to rebuild the window's tabs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecoveryState {
    /// [`VERSION`].
    pub version: u32,
    /// Unix seconds.
    pub saved_at: u64,
    /// Index into `tabs`.
    pub active_tab: usize,
    /// Left to right.
    pub tabs: Vec<TabState>,
}

/// One tab.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TabState {
    /// The user's rename.
    pub title_override: Option<String>,
    /// Header colour.
    pub color: Option<RgbColor>,
    /// The tab's own background choice.
    #[serde(default)]
    pub background: TabBackground,
    /// Index of the focused pane among `layout`'s leaves.
    pub focused: usize,
    /// The panes.
    pub layout: SplitTree<PaneSpec>,
}

/// One pane.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PaneSpec {
    /// Name of its scrollback file ([`valid_key`]).
    pub key: String,
    /// The profile it runs.
    pub profile_id: ProfileId,
    /// The whole profile when it exists nowhere else (quick connect).
    pub ephemeral: Option<Profile>,
    /// Last known working directory (local path, or the remote one for `remember_cwd`).
    pub cwd: Option<String>,
}

/// Why `session.toml` was refused.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// Reading failed.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// Larger than [`MAX_SESSION_BYTES`].
    #[error("the file is too large")]
    TooLarge,
    /// Not valid TOML / wrong shape.
    #[error("{0}")]
    Parse(#[from] toml::de::Error),
    /// Bad pane keys, empty layouts or indexes out of range.
    #[error("invalid content: {0}")]
    Invalid(&'static str),
}

/// A scrollback file name: 1–64 of `[0-9a-z-]` (it comes back from disk, so no path tricks).
#[must_use]
pub fn valid_key(key: &str) -> bool {
    (1..=64).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() || b == b'-')
}

/// `scrollback/<key>.json` under `dir`.
#[must_use]
pub fn scrollback_path(dir: &Path, key: &str) -> PathBuf {
    dir.join(SCROLLBACK_DIR).join(format!("{key}.json"))
}

/// `scrollback/<key>.enc` under `dir`.
#[must_use]
pub fn encrypted_scrollback_path(dir: &Path, key: &str) -> PathBuf {
    dir.join(SCROLLBACK_DIR).join(format!("{key}.enc"))
}

/// Reads `dir/session.toml`: `Ok(None)` when there is none or it was written by a newer build
/// (left alone), `Err` when it is unreadable or invalid (the caller keeps it as
/// [`CORRUPT_FILE`]).
pub fn load(dir: &Path) -> Result<Option<RecoveryState>, RecoveryError> {
    let path = dir.join(SESSION_FILE);
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    if meta.len() > MAX_SESSION_BYTES {
        return Err(RecoveryError::TooLarge);
    }
    let text = std::fs::read_to_string(&path)?;
    let mut state: RecoveryState = toml::from_str(&text)?;
    if state.version > VERSION {
        return Ok(None);
    }
    for tab in &mut state.tabs {
        let leaves = tab.layout.leaves();
        if leaves.is_empty() {
            return Err(RecoveryError::Invalid("a tab without panes"));
        }
        if leaves.iter().any(|p| !valid_key(&p.key)) {
            return Err(RecoveryError::Invalid("a bad pane key"));
        }
        tab.focused = tab.focused.min(leaves.len() - 1);
        tab.layout.clamp_ratios();
    }
    state.active_tab = state.active_tab.min(state.tabs.len().saturating_sub(1));
    Ok(Some(state))
}

/// Writes `state` to `dir/session.toml` (`dir` created `0700`, file `0600`, atomic).
pub fn save(dir: &Path, state: &RecoveryState) -> io::Result<()> {
    let text = toml::to_string(state).map_err(io::Error::other)?;
    save_text(dir, &text)
}

/// Writes already serialised `session.toml` text.
pub fn save_text(dir: &Path, text: &str) -> io::Result<()> {
    fsutil::create_private_dir(dir)?;
    fsutil::write_private_atomic(&dir.join(SESSION_FILE), text.as_bytes())
}

/// Writes one pane's scrollback JSON (`scrollback/` created `0700`, file `0600`, atomic).
pub fn save_scrollback(dir: &Path, key: &str, json: &[u8]) -> io::Result<()> {
    if !valid_key(key) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad pane key"));
    }
    fsutil::create_private_dir(&dir.join(SCROLLBACK_DIR))?;
    fsutil::write_private_atomic(&scrollback_path(dir, key), json)
}

/// Writes one pane's encrypted scrollback (`scrollback/` created `0700`, file `0600`, atomic).
pub fn save_encrypted_scrollback(dir: &Path, key: &str, sealed: &[u8]) -> io::Result<()> {
    if !valid_key(key) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad pane key"));
    }
    fsutil::create_private_dir(&dir.join(SCROLLBACK_DIR))?;
    fsutil::write_private_atomic(&encrypted_scrollback_path(dir, key), sealed)
}

/// Deletes scrollback files whose key and kind are not in the matching keep set, then the oldest
/// files until all of them fit in `max_total` bytes. `keep_encrypted = None` leaves every encrypted
/// file alone while its keyring key is unavailable.
pub fn prune_scrollback(
    dir: &Path,
    keep_plain: &BTreeSet<String>,
    keep_encrypted: Option<&BTreeSet<String>>,
    max_total: u64,
) -> io::Result<()> {
    let sb = dir.join(SCROLLBACK_DIR);
    let entries = match std::fs::read_dir(&sb) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let key = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let extension = path.extension().and_then(|e| e.to_str());
        let keep = match extension {
            Some("json") => keep_plain.contains(&key),
            Some("enc") => keep_encrypted.is_none_or(|keys| keys.contains(&key)),
            _ => false,
        };
        if !keep {
            let _gone = std::fs::remove_file(&path);
            continue;
        }
        if extension == Some("enc") && keep_encrypted.is_none() {
            continue;
        }
        let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        files.push((modified, meta.len(), path));
    }
    files.sort_by_key(|(modified, ..)| *modified);
    let mut total: u64 = files.iter().map(|(_, len, _)| len).sum();
    for (_, len, path) in files {
        if total <= max_total {
            break;
        }
        std::fs::remove_file(&path)?;
        total = total.saturating_sub(len);
    }
    Ok(())
}

/// Deletes every encrypted scrollback file, leaving local scrollback and the layout alone.
pub fn clear_encrypted_scrollback(dir: &Path) -> io::Result<()> {
    let entries = match std::fs::read_dir(dir.join(SCROLLBACK_DIR)) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "enc")
            && entry.file_type().is_ok_and(|kind| kind.is_file())
        {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

/// Deletes `session.toml` and every scrollback file ("Clear saved sessions", recovery off).
pub fn clear(dir: &Path) -> io::Result<()> {
    for result in [
        std::fs::remove_file(dir.join(SESSION_FILE)),
        std::fs::remove_dir_all(dir.join(SCROLLBACK_DIR)),
    ] {
        match result {
            Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
