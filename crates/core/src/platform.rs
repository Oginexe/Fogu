//! Platform paths and host conventions.
//!
//! Everything Linux-specific that used to be spread across the config, recovery and session
//! code lives here, so the rest of the workspace can use one vocabulary for "the user's
//! config directory", "the state directory", "home" and "`known_hosts`".
//!
//! On Linux these are the XDG directories (and still `$XDG_*`-aware); on Windows they are the
//! roaming (`%APPDATA%`) and local (`%LOCALAPPDATA%`) app-data directories.

use std::path::PathBuf;

/// The application's directory name under the platform's config/state root.
pub const APP_DIR: &str = "fogu";

/// The user's home directory.
#[must_use]
pub fn home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

/// `$XDG_CONFIG_HOME/fogu` on Unix, `%APPDATA%\fogu` on Windows.
#[must_use]
pub fn config_dir() -> PathBuf {
    #[cfg(unix)]
    {
        xdg::BaseDirectories::with_prefix(APP_DIR)
            .get_config_home()
            .unwrap_or_else(|| PathBuf::from(".config/fogu"))
    }
    #[cfg(windows)]
    {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(APP_DIR)
    }
}

/// `$XDG_STATE_HOME/fogu` on Unix (`~/.local/state/fogu` by default), `%LOCALAPPDATA%\fogu`
/// on Windows. `None` when no base directory is known: never a path relative to the working
/// directory.
#[must_use]
pub fn state_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".local/state")));
    #[cfg(windows)]
    let base = dirs::data_local_dir();
    base.map(|base| base.join(APP_DIR))
}

/// The user's download directory, used by SFTP double-click downloads.
#[must_use]
pub fn download_dir() -> Option<PathBuf> {
    dirs::download_dir()
}

/// The per-user OpenSSH client configuration.
#[must_use]
pub fn ssh_config_path() -> Option<PathBuf> {
    home_dir().map(|home| home.join(".ssh").join("config"))
}

/// `known_hosts` files to consult, most specific first: Fogu's own file under [`config_dir`],
/// then the user's `~/.ssh/known_hosts`, then the system-wide file.
#[must_use]
pub fn known_hosts_files() -> Vec<PathBuf> {
    let mut out = vec![config_dir().join("known_hosts")];
    if let Some(home) = home_dir() {
        out.push(home.join(".ssh").join("known_hosts"));
    }
    if let Some(system) = system_known_hosts() {
        out.push(system);
    }
    out
}

/// The system-wide `known_hosts`, if the platform has one.
#[must_use]
pub fn system_known_hosts() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(PathBuf::from("/etc/ssh/ssh_known_hosts"))
    }
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData").map(|program_data| {
            PathBuf::from(program_data)
                .join("ssh")
                .join("ssh_known_hosts")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_directories_end_with_the_app_name() {
        assert!(config_dir().ends_with(APP_DIR));
        assert!(state_dir().is_none_or(|dir| dir.ends_with(APP_DIR)));
    }

    #[test]
    fn known_hosts_starts_with_fogus_own_file() {
        let files = known_hosts_files();
        assert_eq!(files.first(), Some(&config_dir().join("known_hosts")));
    }
}
