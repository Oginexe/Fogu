//! What a link click may open: web and mail links anywhere; files only from a local pane, and only
//! if they exist (executables are refused by `open_local`); every other scheme is blocked.
//! Everything goes through [`App::open_link`].

use std::path::{Path, PathBuf};

use fogu_term::links::{Link, LinkKind};
use iced::Task;

use crate::app::App;
use crate::message::Message;
use crate::notifications::{Level, Notification};
use crate::tab::PaneId;

/// What a link resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// Handed to `xdg-open` as is (`http`, `https`, `mailto`).
    Url(String),
    /// A local file or directory that exists.
    File(PathBuf),
}

/// Schemes opened in any pane.
const WEB: [&str; 3] = ["http", "https", "mailto"];

/// The scheme of `uri` (`None` for a plain path).
fn scheme(uri: &str) -> Option<&str> {
    let (scheme, _) = uri.split_once(':')?;
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c));
    valid.then_some(scheme)
}

/// The path of a local `file:` URI; `None` for a remote host or a malformed URI.
fn file_uri_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.get(5..)?.strip_prefix("//")?;
    #[cfg(windows)]
    {
        // `file:///C:/x` and `file://C:/x` are local; `file://server/share` is not.
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        let bytes = rest.as_bytes();
        let drive =
            bytes.get(1) == Some(&b':') && bytes.first().is_some_and(u8::is_ascii_alphabetic);
        drive.then(|| PathBuf::from(rest))
    }
    #[cfg(unix)]
    {
        rest.starts_with('/').then(|| PathBuf::from(rest))
    }
}

/// What `link` may open in a pane that is `local` (else SSH) with working directory `cwd`;
/// `Err` says why not (shown as a toast / disabled menu item).
pub fn resolve(link: &Link, local: bool, cwd: Option<&Path>) -> Result<Target, String> {
    let uri = link.uri.as_str();
    if uri.is_empty() || uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("The link contains spaces or control characters".to_owned());
    }
    let path = match (link.kind, scheme(uri)) {
        (LinkKind::Path, _) => PathBuf::from(uri),
        // Windows reads `\\` in a web link as `/`; a URL never needs one.
        (_, Some(s)) if WEB.iter().any(|w| s.eq_ignore_ascii_case(w)) => {
            if uri.contains('\\') {
                return Err("A web link with a backslash is not opened".to_owned());
            }
            return Ok(Target::Url(uri.to_owned()));
        }
        // Only a local `file:///path` (or `file://C:/path` on Windows): a host would reach out
        // to a server the output chose.
        (_, Some(s)) if s.eq_ignore_ascii_case("file") => {
            file_uri_path(uri).ok_or("Only local file:/// links can be opened")?
        }
        (_, Some(s)) => return Err(format!("Blocked link scheme \u{201c}{s}\u{201d}")),
        (_, None) => return Err("Not a link that can be opened".to_owned()),
    };
    if !local {
        return Err("A path on the remote host: use Copy link".to_owned());
    }
    // shortcut: `file://` paths are not percent-decoded; fine for the plain paths tools print.
    let path = match path.strip_prefix("~") {
        Ok(rest) => std::env::home_dir().ok_or("No home directory")?.join(rest),
        Err(_) if path.is_relative() && !path.has_root() => cwd
            .ok_or("The shell has not reported its directory (OSC 7)")?
            .join(path),
        Err(_) => path,
    };
    if !fogu_core::platform::is_local_path(&path) {
        return Err("A network path is never opened from a link".to_owned());
    }
    if !path.exists() {
        return Err(format!("{} does not exist", path.display()));
    }
    Ok(Target::File(path))
}

impl App {
    /// The link messages (dispatched from `App::update`).
    pub(crate) fn on_link_message(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::LinkHover(pane, link) => {
                if let Some(p) = self.pane_mut(pane) {
                    p.link = link;
                }
                Task::none()
            }
            Message::OpenLink(pane, link) => {
                self.menu = None;
                self.open_link(pane, &link)
            }
            Message::CopyLink(text) => {
                self.menu = None;
                iced::clipboard::write(text)
            }
            _ => Task::none(),
        }
    }

    /// Ctrl+click or "Open link" on `link` in pane `pane`.
    pub(crate) fn open_link(&mut self, pane: PaneId, link: &Link) -> Task<Message> {
        let Some(p) = self.pane(pane) else {
            return Task::none();
        };
        match resolve(link, !p.is_ssh(), p.local_cwd.as_deref()) {
            Ok(Target::File(path)) => self.open_local(path),
            Ok(Target::Url(url)) => self.open_url(url),
            Err(why) => self.notify(Notification::new(Level::Warn, "Link not opened").detail(why)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests")]

    use super::*;

    fn link(uri: &str, kind: LinkKind) -> Link {
        Link {
            uri: uri.to_owned(),
            kind,
            row: 0,
            start: 0,
            end: 1,
        }
    }

    #[test]
    fn allow_list() {
        use LinkKind::{Hyperlink as H, Path as P, Url as U};
        let tmp = std::env::temp_dir();
        let cwd = Some(tmp.as_path());
        let blocked = |r: Result<Target, String>| r.unwrap_err();
        assert_eq!(
            resolve(&link("https://example.org", H), false, None),
            Ok(Target::Url("https://example.org".into()))
        );
        assert!(resolve(&link("HTTP://a.io", U), true, None).is_ok());
        assert!(resolve(&link("mailto:me@a.io", H), false, None).is_ok());
        assert!(
            blocked(resolve(&link("javascript:alert(1)", H), true, cwd)).contains("javascript")
        );
        assert!(blocked(resolve(&link("ssh://host", H), true, cwd)).contains("ssh"));
        assert!(blocked(resolve(&link("ftp://files.lan/a", U), true, cwd)).contains("ftp"));
        assert!(blocked(resolve(&link("file://evil.host/share", H), true, cwd)).contains("local"));
        assert!(blocked(resolve(&link("https://a.io/\u{7}x", H), true, cwd)).contains("control"));
        assert!(blocked(resolve(&link(r"https:\\evil\share", H), true, cwd)).contains("backslash"));
        // Files: local panes only, and only when they exist.
        let here = tmp.to_string_lossy().into_owned();
        assert_eq!(
            resolve(&link(&format!("file://{here}"), H), true, None),
            Ok(Target::File(tmp.clone()))
        );
        assert!(
            blocked(resolve(&link(&format!("file://{here}"), H), false, None)).contains("remote")
        );
        assert_eq!(
            resolve(&link(&here, P), true, None),
            Ok(Target::File(tmp.clone()))
        );
        assert!(blocked(resolve(&link(&here, P), false, None)).contains("Copy link"));
        assert!(blocked(resolve(&link("/no/such/file", P), true, None)).contains("does not exist"));
        let name = tmp.file_name().unwrap().to_string_lossy().into_owned();
        let parent = tmp.parent().unwrap();
        assert_eq!(
            resolve(&link(&name, P), true, Some(parent)),
            Ok(Target::File(parent.join(&name)))
        );
        assert!(blocked(resolve(&link("rel/x", P), true, None)).contains("OSC 7"));
    }

    /// Even `exists()` on a UNC path connects to the host and sends the user's NTLM hash.
    #[cfg(windows)]
    #[test]
    fn network_paths_are_never_touched() {
        use LinkKind::{Hyperlink as H, Path as P};
        let share = Some(Path::new(r"\\localhost\c$"));
        for (uri, kind, cwd) in [
            (r"\\localhost\c$\Windows", P, None),
            ("//localhost/c$/Windows", P, None),
            ("file:////localhost/c$/Windows", H, None),
            ("Windows", P, share),
        ] {
            let why = resolve(&link(uri, kind), true, cwd).unwrap_err();
            assert!(
                why.contains("network") || why.contains("local"),
                "{uri}: {why}"
            );
        }
    }
}
