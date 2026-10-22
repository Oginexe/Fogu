//! Recently opened profiles (the "Recent" list): ids + Unix timestamps, newest first,
//! capped at [`CAP`], kept in `$XDG_STATE_HOME/fogu/recent.toml` (mode 0600, atomic
//! rewrite through [`fsutil`](crate::fsutil)). An id may be a stored profile, a built-in
//! (`builtin:…`) or a quick-connect string (`quick:user@host:port`); the UI resolves them and
//! skips ids that no longer exist.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fsutil;
use crate::profile::ProfileId;

/// File name inside the state directory.
pub const RECENT_FILE: &str = "recent.toml";
/// Most entries kept.
pub const CAP: usize = 20;

/// One opened profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentEntry {
    /// The profile (or quick-connect) id.
    pub id: ProfileId,
    /// When it was last opened, seconds since the Unix epoch.
    pub at: u64,
}

/// The recent list, newest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recent {
    /// Entries, newest first, at most [`CAP`], ids unique.
    #[serde(default)]
    pub recent: Vec<RecentEntry>,
}

/// Why the recent file could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum RecentError {
    /// Reading or writing failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The file is not valid TOML of this shape.
    #[error("{0}")]
    Parse(#[from] toml::de::Error),
    /// Serialisation failed (should not happen).
    #[error("{0}")]
    Serialize(#[from] toml::ser::Error),
}

impl Recent {
    /// Reads `path`; a missing file is an empty list.
    pub fn load(path: &Path) -> Result<Self, RecentError> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let mut recent: Self = toml::from_str(&text)?;
                recent.recent.truncate(CAP);
                Ok(recent)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err.into()),
        }
    }

    /// Replaces `path` (its directory is created 0700 if missing) with this list, 0600.
    pub fn save(&self, path: &Path) -> Result<(), RecentError> {
        if let Some(dir) = path.parent() {
            fsutil::create_private_dir(dir)?;
        }
        let text = toml::to_string(self)?;
        Ok(fsutil::write_private_atomic(path, text.as_bytes())?)
    }

    /// Moves `id` to the front (or adds it) with time `at`, dropping the oldest beyond [`CAP`].
    pub fn touch(&mut self, id: &ProfileId, at: u64) {
        self.recent.retain(|e| &e.id != id);
        self.recent.insert(0, RecentEntry { id: id.clone(), at });
        self.recent.truncate(CAP);
    }

    /// When `id` was last opened.
    #[must_use]
    pub fn last_used(&self, id: &ProfileId) -> Option<u64> {
        self.recent.iter().find(|e| &e.id == id).map(|e| e.at)
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests")]

    use super::*;

    fn id(s: &str) -> ProfileId {
        ProfileId(s.to_owned())
    }

    #[test]
    fn touch_moves_to_front_and_caps() {
        let mut recent = Recent::default();
        for n in 0..25 {
            recent.touch(&id(&format!("p{n}")), n);
        }
        assert_eq!(recent.recent.len(), CAP);
        assert_eq!(recent.recent[0].id, id("p24"));
        assert_eq!(recent.recent[CAP - 1].id, id("p5"));
        recent.touch(&id("p10"), 100);
        let ids: Vec<&str> = recent
            .recent
            .iter()
            .take(3)
            .map(|e| e.id.0.as_str())
            .collect();
        assert_eq!(ids, ["p10", "p24", "p23"]);
        assert_eq!(recent.recent.len(), CAP);
        assert_eq!(recent.last_used(&id("p10")), Some(100));
        assert_eq!(recent.last_used(&id("p0")), None);
    }

    #[test]
    fn saves_0600_and_loads_back() {
        let dir = std::env::temp_dir().join(format!("fogu-recent-{}", std::process::id()));
        let path = dir.join("state").join(RECENT_FILE);
        assert_eq!(Recent::load(&path).unwrap(), Recent::default());
        let mut recent = Recent::default();
        recent.touch(&id("quick:me@h:2222"), 7);
        recent.touch(&id("work"), 9);
        recent.save(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(Recent::load(&path).unwrap(), recent);
        std::fs::write(&path, "recent = 5").unwrap();
        assert!(Recent::load(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
