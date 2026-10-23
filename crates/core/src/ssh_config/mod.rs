//! `~/.ssh/config` read-only import: every plain `Host` alias becomes an SSH
//! profile resolved with OpenSSH semantics. Never written.
//!
//! Semantics (`ssh_config(5)`): blocks apply in file order and, per keyword, the **first** value
//! obtained wins, so `Host *` blocks act as defaults when they come last and as overrides when
//! they come first. Multi-valued keywords (`IdentityFile`, the forwards, …) accumulate.
//! `Include` (globs; relative paths under `~/.ssh/`) is read where it appears, inside the
//! enclosing `Host` block's condition; it is bounded (depth, file count, sizes) and cycle-safe.
//! `Match` blocks are recognised and skipped with a warning. Lexing problems are [`Issue`]s with
//! `file:line`; the rest of the file still loads. Mapping into profile options is in
//! `profiles.rs`.
//!
//! The file is attacker-ish input (imported config): names are checked, texts capped, and
//! security-relevant keywords (`StrictHostKeyChecking`, `UserKnownHostsFile`) are reported,
//! never obeyed.

mod lex;
mod profiles;

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

pub use lex::{glob, host_matches};
pub use profiles::ID_PREFIX;

/// `Include` nesting limit (OpenSSH's own).
pub const MAX_DEPTH: usize = 16;
/// Files read per load (the top file and every include).
pub const MAX_FILES: usize = 128;
/// Bytes per file.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Bytes over all files.
pub const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024;
/// Bytes per line.
pub const MAX_LINE: usize = 4096;
/// Issues kept per load (the rest is counted in the last one).
const MAX_ISSUES: usize = 50;

/// Where `~`, `%d` and `%u` point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Env {
    /// The user's home directory.
    pub home: PathBuf,
    /// The local user name.
    pub user: String,
}

impl Env {
    /// The platform home directory and local user name; `None` without a usable home.
    #[must_use]
    pub fn from_process() -> Option<Self> {
        let home = crate::platform::home_dir()?;
        home.is_absolute().then(|| Self {
            home,
            user: crate::config::ssh_opts::local_user(),
        })
    }

    /// `~/.ssh/config`.
    #[must_use]
    pub fn user_config(&self) -> PathBuf {
        self.home.join(".ssh").join("config")
    }
}

/// A problem in the file, with its location; the rest of the file still loads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// The file (the top file or an include).
    pub file: PathBuf,
    /// 1-based line; 0 = the file as a whole.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line == 0 {
            write!(f, "{}: {}", self.file.display(), self.message)
        } else {
            write!(f, "{}:{}: {}", self.file.display(), self.line, self.message)
        }
    }
}

/// Options of one `Host` block (or the part of it between two `Include`s).
#[derive(Clone, Debug)]
struct Block {
    /// Pattern lists that must all match: the block's own `Host` line plus the `Host` lines
    /// around the `Include`s that led here. Empty = applies to every host.
    conds: Vec<Vec<String>>,
    options: Vec<lex::Directive>,
}

/// A file or directory read during the load, with what it looked like (`None` = missing).
type Stamp = (PathBuf, Option<(SystemTime, u64)>);

/// A loaded `~/.ssh/config` (and its includes).
#[derive(Clone, Debug, Default)]
pub struct SshConfig {
    blocks: Vec<Block>,
    /// Plain `Host` aliases in file order, de-duplicated (case-insensitive).
    aliases: Vec<String>,
    /// Problems found while reading.
    pub issues: Vec<Issue>,
    stamps: Vec<Stamp>,
}

impl SshConfig {
    /// Reads `path` and its includes; a missing file is an empty config.
    #[must_use]
    pub fn load(path: &Path, env: &Env) -> Self {
        let mut loader = Loader {
            env,
            out: Self::default(),
            stack: Vec::new(),
            files: 0,
            bytes: 0,
        };
        loader.read_file(path, &[], 0);
        if loader.out.issues.len() > MAX_ISSUES {
            let more = loader.out.issues.len() - MAX_ISSUES;
            loader.out.issues.truncate(MAX_ISSUES);
            loader.out.issues.push(Issue {
                file: path.to_owned(),
                line: 0,
                message: format!("{more} more problems not shown"),
            });
        }
        loader.out
    }

    /// Whether any file or globbed directory read by [`load`](Self::load) changed since (mtime
    /// or size), appeared or vanished.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.stamps.iter().any(|(path, seen)| &stamp(path) != seen)
    }

    /// The options of one jump hop named by a `ProxyJump` value (`jump_host =
    /// "ssh-config:<spec>"`): the last `[user@]host[:port]` of `spec`, configured like OpenSSH
    /// configures a `-J` destination (the host's own `Host` blocks, then the given user/port).
    /// With earlier hops, it jumps through `ssh-config:<the earlier hops>` instead of its own
    /// `ProxyJump`/`ProxyCommand`.
    ///
    /// # Errors
    /// The reason when the last hop is not `[user@]host[:port]`.
    pub fn jump_opts(&self, spec: &str, env: &Env) -> Result<crate::SshOpts, String> {
        let (outer, last) = match spec.rsplit_once(',') {
            Some((outer, last)) => (Some(outer), last),
            None => (None, spec),
        };
        let (user, host, port) =
            profiles::parse_hop(last).ok_or_else(|| format!("invalid ProxyJump hop {last}"))?;
        let mut opts = self.ssh_opts(&host, env);
        if user.is_some() {
            opts.user = user;
        }
        if port.is_some() {
            opts.port = port;
        }
        if let Some(outer) = outer {
            opts.jump_host = Some(crate::ProfileId(format!("{ID_PREFIX}{outer}")));
            opts.proxy_command = None;
        }
        Ok(opts)
    }

    /// The plain `Host` aliases, in file order.
    #[must_use]
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }

    /// The directives that apply to `alias`, first value per keyword (multi-valued keywords
    /// keep every value), in file order.
    fn options_for(&self, alias: &str) -> Vec<&lex::Directive> {
        let mut seen: Vec<&str> = Vec::new();
        let mut out = Vec::new();
        let applies = |b: &&Block| {
            b.conds
                .iter()
                .all(|c| host_matches(c.iter().map(String::as_str), alias))
        };
        for block in self.blocks.iter().filter(applies) {
            for d in &block.options {
                if profiles::MULTI.contains(&d.key.as_str()) {
                    out.push(d);
                } else if !seen.contains(&d.key.as_str()) {
                    seen.push(&d.key);
                    out.push(d);
                }
            }
        }
        out
    }
}

/// Modification time and size of a file; for a globbed directory, its number of entries instead
/// of a size (always 0 on Windows, fixed on ext4), as its time can lag behind a new file.
fn stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let size = if meta.is_dir() {
        std::fs::read_dir(path).ok()?.count() as u64
    } else {
        meta.len()
    };
    Some((meta.modified().ok()?, size))
}

struct Loader<'a> {
    env: &'a Env,
    out: SshConfig,
    /// Canonical paths of the files being read (cycle detection).
    stack: Vec<PathBuf>,
    files: usize,
    bytes: u64,
}

impl Loader<'_> {
    fn issue(&mut self, file: &Path, line: usize, message: impl Into<String>) {
        self.out.issues.push(Issue {
            file: file.to_owned(),
            line,
            message: message.into(),
        });
    }

    fn read_file(&mut self, path: &Path, outer: &[Vec<String>], depth: usize) {
        self.out.stamps.push((path.to_owned(), stamp(path)));
        let Some(text) = self.read_text(path) else {
            return;
        };
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
        self.stack.push(canonical);
        self.parse(path, &text, outer, depth);
        self.stack.pop();
    }

    /// The file's text, or `None` (missing: silently, like OpenSSH; anything else: an issue).
    fn read_text(&mut self, path: &Path) -> Option<String> {
        let meta = std::fs::metadata(path).ok()?;
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
        let refuse = if !meta.is_file() {
            Some("not a regular file; ignored".to_owned())
        } else if self.stack.contains(&canonical) {
            Some("Include cycle; ignored".to_owned())
        } else if self.files >= MAX_FILES {
            Some(format!("more than {MAX_FILES} files; ignored"))
        } else if meta.len() > MAX_FILE_BYTES || self.bytes + meta.len() > MAX_TOTAL_BYTES {
            Some("too large; ignored".to_owned())
        } else {
            None
        };
        if let Some(why) = refuse {
            self.issue(path, 0, why);
            return None;
        }
        self.files += 1;
        let mut bytes = Vec::new();
        let read = File::open(path).and_then(|file| {
            // Checked again on the open file: it may have been swapped since the stat.
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::other("not a regular file"));
            }
            file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)
        });
        match read {
            Ok(n) if n as u64 > MAX_FILE_BYTES => {
                self.issue(path, 0, "too large; ignored");
                None
            }
            Ok(n) => {
                self.bytes += n as u64;
                Some(String::from_utf8_lossy(&bytes).into_owned())
            }
            Err(err) => {
                self.issue(path, 0, format!("unreadable: {err}"));
                None
            }
        }
    }

    fn parse(&mut self, file: &Path, text: &str, outer: &[Vec<String>], depth: usize) {
        let mut conds = outer.to_vec();
        let mut options = Vec::new();
        let mut skipping = false;
        for (index, line) in text.lines().enumerate() {
            let n = index + 1;
            if line.len() > MAX_LINE {
                self.issue(
                    file,
                    n,
                    format!("line longer than {MAX_LINE} bytes; ignored"),
                );
                continue;
            }
            let directive = match lex::lex(line) {
                Ok(Some(d)) => d,
                Ok(None) => continue,
                Err(why) => {
                    self.issue(file, n, format!("{why}; line ignored"));
                    continue;
                }
            };
            match directive.key.as_str() {
                "host" | "match" => {
                    self.flush(&conds, &mut options);
                    skipping = directive.key == "match";
                    if skipping {
                        self.issue(file, n, "Match blocks are not supported; block skipped");
                    } else if directive.args.is_empty() {
                        self.issue(file, n, "Host without patterns; block skipped");
                        skipping = true;
                    } else {
                        self.host_line(&directive.args, outer, &mut conds);
                    }
                }
                _ if skipping => {}
                "include" => {
                    self.flush(&conds, &mut options);
                    if directive.args.is_empty() {
                        self.issue(file, n, "Include without a path");
                    }
                    for arg in &directive.args {
                        self.include(arg, &conds, depth + 1, (file, n));
                    }
                }
                _ => options.push(directive),
            }
        }
        self.flush(&conds, &mut options);
    }

    fn host_line(
        &mut self,
        patterns: &[String],
        outer: &[Vec<String>],
        conds: &mut Vec<Vec<String>>,
    ) {
        conds.clear();
        conds.extend_from_slice(outer);
        conds.push(patterns.to_vec());
        for alias in patterns.iter().filter(|p| lex::is_plain_alias(p)) {
            let known = self
                .out
                .aliases
                .iter()
                .any(|a| a.eq_ignore_ascii_case(alias));
            if !known {
                self.out.aliases.push(alias.clone());
            }
        }
    }

    fn flush(&mut self, conds: &[Vec<String>], options: &mut Vec<lex::Directive>) {
        if !options.is_empty() {
            self.out.blocks.push(Block {
                conds: conds.to_vec(),
                options: std::mem::take(options),
            });
        }
    }

    fn include(&mut self, arg: &str, conds: &[Vec<String>], depth: usize, at: (&Path, usize)) {
        if depth > MAX_DEPTH {
            self.issue(
                at.0,
                at.1,
                format!("Include nested deeper than {MAX_DEPTH}; ignored"),
            );
            return;
        }
        let path = if let Some(rest) = arg.strip_prefix("~/") {
            self.env.home.join(rest)
        } else if arg == "~" || arg.starts_with('~') {
            self.issue(
                at.0,
                at.1,
                format!("Include {arg}: only ~/ is supported; ignored"),
            );
            return;
        } else {
            // Relative paths are under ~/.ssh (ssh_config(5), user configuration).
            self.env.home.join(".ssh").join(arg)
        };
        for file in self.expand(&path) {
            self.read_file(&file, conds, depth);
        }
    }

    /// `glob(3)` for `*`/`?` in any component (sorted, hidden names only for patterns starting
    /// with `.`); globbed directories are stamped so a new file triggers a reload.
    fn expand(&mut self, path: &Path) -> Vec<PathBuf> {
        let mut found = vec![PathBuf::new()];
        for part in path.components() {
            let Component::Normal(name) = part else {
                for p in &mut found {
                    p.push(part);
                }
                continue;
            };
            let name = name.to_string_lossy();
            if !name.contains(['*', '?']) {
                for p in &mut found {
                    p.push(&*name);
                }
                continue;
            }
            let mut next = Vec::new();
            for dir in &found {
                self.out.stamps.push((dir.clone(), stamp(dir)));
                let Ok(list) = std::fs::read_dir(dir) else {
                    continue;
                };
                let mut names: Vec<String> = list
                    .filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .filter(|n| !n.starts_with('.') || name.starts_with('.'))
                    .filter(|n| glob(name.as_bytes(), n.as_bytes()))
                    .collect();
                names.sort();
                next.extend(names.into_iter().map(|n| dir.join(n)));
                if next.len() > MAX_FILES {
                    break;
                }
            }
            found = next;
        }
        found
    }
}

#[cfg(test)]
mod tests;
