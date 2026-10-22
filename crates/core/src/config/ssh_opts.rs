//! SSH profile options: the stored partial form [`SshOpts`] and the resolved [`EffectiveSsh`].
//!
//! Stored fields are `Option<T>` like every other profile option: a profile inherits unset
//! fields from `profile_defaults.ssh`, which inherits from the builtin defaults below (`user`
//! defaults to `$USER`).
//! Options whose behaviour is not implemented yet are accepted and listed by
//! [`EffectiveSsh::unsupported`], which the session warns about once at connect.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::route::Jump;
use crate::profile::{Osc52Policy, ProfileId};

/// Default SSH port.
pub const DEFAULT_SSH_PORT: u16 = 22;
/// Default keepalive interval, in milliseconds.
pub const DEFAULT_KEEPALIVE_INTERVAL_MS: u64 = 5000;
/// Default number of unanswered keepalives before the connection is dropped.
pub const DEFAULT_KEEPALIVE_COUNT_MAX: u32 = 10;
/// Default PTY `TERM`.
pub const DEFAULT_TERM: &str = "xterm-256color";
/// How long a connect-time prompt (password, host key…) waits for an answer, in milliseconds.
pub const DEFAULT_PROMPT_TIMEOUT_MS: u64 = 120_000;
/// Seconds an RSA key added to the agent by Fogu stays there.
pub const DEFAULT_AGENT_KEY_LIFETIME_S: u32 = 3600;
/// Seconds a reused connection stays open after its last tab closed.
pub const DEFAULT_REUSE_LINGER_S: u32 = 10;

/// Stored option names whose behaviour is not implemented yet: the profile editor marks them
/// "not supported yet". [`EffectiveSsh::unsupported`] warns about the same options at connect
/// time when they are set.
pub const NOT_SUPPORTED_YET: &[&str] = &["input_backspace"];

/// Which authentication methods to try.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAuth {
    /// The full order: none → agent → private keys → password → keyboard-interactive.
    #[default]
    Auto,
    /// Password only.
    Password,
    /// Private key files only.
    PublicKey,
    /// SSH agent identities only.
    Agent,
    /// Keyboard-interactive only.
    KeyboardInteractive,
}

/// What the Backspace key sends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backspace {
    /// The terminal's normal encoding (DEL, `^?`).
    #[default]
    Backspace,
    /// `^H`.
    CtrlH,
    /// `^?`.
    #[serde(rename = "ctrl-?")]
    CtrlQuestion,
    /// The Delete key sequence (`ESC [3~`).
    Delete,
}

/// Port forward direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardKind {
    /// `-L`: listen locally, connect from the server.
    #[default]
    Local,
    /// `-R`: listen on the server, connect locally.
    Remote,
    /// `-D`: local SOCKS5 server.
    Dynamic,
}

/// Listen address of a forward whose `host` is empty: loopback only.
pub const DEFAULT_FORWARD_HOST: &str = "127.0.0.1";

/// One port forward, started with the session (`forwarded_ports`) or added at runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortForward {
    /// Direction.
    #[serde(rename = "type")]
    pub kind: ForwardKind,
    /// Listen address (local for `Local`/`Dynamic`, on the server for `Remote`); empty =
    /// [`DEFAULT_FORWARD_HOST`].
    #[serde(skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// Listen port.
    pub port: u16,
    /// Target address (unused for `Dynamic`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target_address: String,
    /// Target port (unused for `Dynamic`).
    pub target_port: u16,
    /// Free text shown in the forwards dialog.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
}

impl PortForward {
    /// The address to listen on: `host` trimmed, or [`DEFAULT_FORWARD_HOST`] when empty.
    #[must_use]
    pub fn bind_host(&self) -> &str {
        match self.host.trim() {
            "" => DEFAULT_FORWARD_HOST,
            host => host,
        }
    }

    /// `true` when the listener is reachable from other machines (not a loopback address):
    /// the UI warns about it.
    #[must_use]
    pub fn is_exposed(&self) -> bool {
        let host = self.bind_host();
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        !(host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()))
    }

    /// Why this forward can't start, if it can't (listen port 0, missing target).
    #[must_use]
    pub fn problem(&self) -> Option<&'static str> {
        if self.port == 0 {
            return Some("the listen port must be 1–65535");
        }
        if self.kind != ForwardKind::Dynamic {
            if self.target_address.trim().is_empty() {
                return Some("the target address is empty");
            }
            if self.target_port == 0 {
                return Some("the target port must be 1–65535");
            }
        }
        None
    }

    /// `L 127.0.0.1:8080 → web:80` / `R …` / `D 127.0.0.1:1080 (SOCKS)`: unsanitized, the
    /// caller sanitizes before showing it.
    #[must_use]
    pub fn label(&self) -> String {
        let listen = format!("{}:{}", self.bind_host(), self.port);
        match self.kind {
            ForwardKind::Local => {
                format!("L {listen} → {}:{}", self.target_address, self.target_port)
            }
            ForwardKind::Remote => {
                format!("R {listen} → {}:{}", self.target_address, self.target_port)
            }
            ForwardKind::Dynamic => format!("D {listen} (SOCKS)"),
        }
    }
}

/// Per-profile algorithm allow-lists in preference order; an empty list = russh's defaults.
/// Names the SSH library doesn't know are reported (editor issue, connect-time warning) and
/// never sent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Algorithms {
    /// Key exchange.
    pub kex: Vec<String>,
    /// Ciphers.
    pub cipher: Vec<String>,
    /// MACs.
    pub hmac: Vec<String>,
    /// Host key algorithms.
    pub server_host_key: Vec<String>,
    /// Compression.
    pub compression: Vec<String>,
}

impl Algorithms {
    /// `true` when no list overrides russh's defaults.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.lists().iter().all(|list| list.is_empty())
    }

    /// The lists in category order: kex, cipher, hmac, server host key, compression.
    #[must_use]
    pub fn lists(&self) -> [&Vec<String>; 5] {
        [
            &self.kex,
            &self.cipher,
            &self.hmac,
            &self.server_host_key,
            &self.compression,
        ]
    }

    /// Names not in `known` (the transport's names, same category order as [`Self::lists`]),
    /// once each, in order.
    #[must_use]
    pub fn unknown(&self, known: &[Vec<String>; 5]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (list, known) in self.lists().into_iter().zip(known) {
            for name in list {
                if !known.contains(name) && !out.contains(name) {
                    out.push(name.clone());
                }
            }
        }
        out
    }
}

/// One login-script rule: when output matches `expect`, send `send`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginScript {
    /// Text (or regex) to wait for.
    pub expect: String,
    /// Text to send (escapes like `\n` are processed).
    pub send: String,
    /// `expect` is a regular expression.
    pub is_regex: bool,
    /// Skip this rule if it never matches.
    pub optional: bool,
}

/// Stored (partial) SSH options; see the module docs. Durations are milliseconds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshOpts {
    /// Hostname or address; required to connect (no builtin default).
    pub host: Option<String>,
    /// TCP port (22).
    pub port: Option<u16>,
    /// Remote user (`$USER` at resolve time).
    pub user: Option<String>,
    /// Auth method filter (`auto`).
    pub auth: Option<SshAuth>,
    /// Private key files, tried in order (OpenSSH, PKCS#8, PEM, `PuTTY` `.ppk`).
    pub private_keys: Option<Vec<PathBuf>>,
    /// Keepalive interval in ms (5000); 0 disables keepalives.
    pub keepalive_interval: Option<u64>,
    /// Unanswered keepalives before disconnecting (10).
    pub keepalive_count_max: Option<u32>,
    /// Connect + handshake + per-request auth timeout in ms (unset = 20 s).
    pub ready_timeout: Option<u64>,
    /// Don't print the server's auth banner.
    pub skip_banner: Option<bool>,
    /// Confirm before closing a live SSH tab or pane (unset = `true`).
    pub warn_on_close: Option<bool>,
    /// PTY `TERM` (`xterm-256color`).
    pub term: Option<String>,
    /// Backspace encoding.
    pub input_backspace: Option<Backspace>,
    /// Profile to connect through first; the target is reached over a `direct-tcpip` channel
    /// of that connection.
    pub jump_host: Option<ProfileId>,
    /// Command whose stdio is the transport, run by `$SHELL -c` with `%h`/`%p`/`%r`/`%%`
    /// substituted.
    pub proxy_command: Option<String>,
    /// SOCKS5 proxy host.
    pub socks_proxy_host: Option<String>,
    /// SOCKS5 proxy port.
    pub socks_proxy_port: Option<u16>,
    /// Let the SOCKS5 proxy resolve the host name (`true`); `false` resolves it here and sends
    /// the address (leaks the name to the local DNS resolver).
    pub socks_proxy_remote_dns: Option<bool>,
    /// HTTP CONNECT proxy host.
    pub http_proxy_host: Option<String>,
    /// HTTP CONNECT proxy port.
    pub http_proxy_port: Option<u16>,
    /// Auto-started port forwards.
    pub forwarded_ports: Option<Vec<PortForward>>,
    /// Forward the local SSH agent to the server (`false`; tab badge while on).
    pub agent_forward: Option<bool>,
    /// X11 forwarding with a fake cookie, OpenSSH-style (`false`; tab badge while on).
    pub x11: Option<bool>,
    /// Algorithm allow-lists; an empty list keeps russh's defaults.
    pub algorithms: Option<Algorithms>,
    /// Open new tabs, splits and SFTP of this profile on its live connection (`true`).
    pub reuse_session: Option<bool>,
    /// Seconds a reused connection stays open after its last tab closed (10); 0 = close at
    /// once.
    pub reuse_linger: Option<u32>,
    /// Use and offer the desktop Secret Service for this profile's passwords and key
    /// passphrases (`true`).
    pub stored_secrets: Option<bool>,
    /// Login scripts.
    pub scripts: Option<Vec<LoginScript>>,
    /// Remote directory to `cd` into after login.
    pub cwd: Option<String>,
    /// Track the remote cwd and reuse it on reconnect/duplicate.
    pub remember_cwd: Option<bool>,
    /// Clear the "Connecting…" service lines once the shell starts (`true`).
    pub clear_service_messages_on_connect: Option<bool>,
    /// Verify host keys against `known_hosts` (`true`); `false` shows a warning badge.
    pub verify_host_keys: Option<bool>,
    /// Name the host key is looked up and saved under in `known_hosts` instead of the host and
    /// port (OpenSSH `HostKeyAlias`).
    pub host_key_alias: Option<String>,
    /// Manual ordering in the profile list.
    pub weight: Option<i32>,
    /// Per-profile override of `terminal.osc52_write`.
    pub osc52_write: Option<Osc52Policy>,
    /// Offer only the agent identities whose `.pub` sits next to a configured key (OpenSSH
    /// `IdentitiesOnly`; `false`).
    pub identities_only: Option<bool>,
    /// How long a connect-time prompt waits for an answer, in ms (120000); 0 = no limit.
    pub prompt_timeout: Option<u64>,
    /// SSH agent socket (unset = `$SSH_AUTH_SOCK`, then the usual sockets, see the wiki).
    pub agent_path: Option<PathBuf>,
    /// Seconds an RSA key file loaded by Fogu stays in the agent (3600); 0 = until the
    /// agent stops. RSA keys are always signed by the agent, never in Fogu.
    pub agent_key_lifetime: Option<u32>,
    /// `~/.ssh/config` options that apply to this host but are not used (unknown to Fogu,
    /// unusable values, or never obeyed like `StrictHostKeyChecking no`); listed in the
    /// connect-time warning. Only `ssh_config` profiles have them; never stored.
    #[serde(skip)]
    pub ignored_ssh_config: Vec<String>,
}

/// A fully resolved SSH profile, ready for `fogu_session::open`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the flat SSH profile options one to one"
)]
pub struct EffectiveSsh {
    /// Hostname or address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Remote user.
    pub user: String,
    /// See [`SshOpts::auth`].
    pub auth: SshAuth,
    /// See [`SshOpts::private_keys`].
    pub private_keys: Vec<PathBuf>,
    /// `None` = keepalives disabled.
    pub keepalive_interval: Option<Duration>,
    /// See [`SshOpts::keepalive_count_max`].
    pub keepalive_count_max: u32,
    /// `None` = the session's default.
    pub ready_timeout: Option<Duration>,
    /// See [`SshOpts::skip_banner`].
    pub skip_banner: bool,
    /// See [`SshOpts::warn_on_close`].
    pub warn_on_close: bool,
    /// See [`SshOpts::term`].
    pub term: String,
    /// See [`SshOpts::input_backspace`].
    pub input_backspace: Backspace,
    /// See [`SshOpts::jump_host`].
    pub jump_host: Option<ProfileId>,
    /// See [`SshOpts::proxy_command`].
    pub proxy_command: Option<String>,
    /// SOCKS5 proxy `(host, port)`; port defaults to 1080.
    pub socks_proxy: Option<(String, u16)>,
    /// See [`SshOpts::socks_proxy_remote_dns`].
    pub socks_remote_dns: bool,
    /// HTTP proxy `(host, port)`; port defaults to 8080.
    pub http_proxy: Option<(String, u16)>,
    /// See [`SshOpts::forwarded_ports`].
    pub forwarded_ports: Vec<PortForward>,
    /// See [`SshOpts::agent_forward`].
    pub agent_forward: bool,
    /// See [`SshOpts::x11`].
    pub x11: bool,
    /// See [`SshOpts::algorithms`].
    pub algorithms: Algorithms,
    /// See [`SshOpts::reuse_session`].
    pub reuse_session: bool,
    /// See [`SshOpts::reuse_linger`].
    pub reuse_linger: Duration,
    /// See [`SshOpts::stored_secrets`].
    pub stored_secrets: bool,
    /// See [`SshOpts::scripts`].
    pub scripts: Vec<LoginScript>,
    /// See [`SshOpts::cwd`].
    pub cwd: Option<String>,
    /// See [`SshOpts::remember_cwd`].
    pub remember_cwd: bool,
    /// See [`SshOpts::clear_service_messages_on_connect`].
    pub clear_service_messages_on_connect: bool,
    /// See [`SshOpts::verify_host_keys`].
    pub verify_host_keys: bool,
    /// See [`SshOpts::host_key_alias`].
    pub host_key_alias: Option<String>,
    /// See [`SshOpts::weight`].
    pub weight: i32,
    /// See [`SshOpts::identities_only`].
    pub identities_only: bool,
    /// See [`SshOpts::prompt_timeout`]; `None` = no limit.
    pub prompt_timeout: Option<Duration>,
    /// See [`SshOpts::agent_path`]; `None` = discovered.
    pub agent_path: Option<PathBuf>,
    /// See [`SshOpts::agent_key_lifetime`]; `None` = no limit.
    pub agent_key_lifetime: Option<u32>,
    /// See [`SshOpts::ignored_ssh_config`].
    pub ignored_ssh_config: Vec<String>,
    /// The `jump_host` chain, filled by [`resolve_jumps`](super::route::resolve_jumps) (the
    /// session never looks profiles up itself).
    pub jump: Jump,
}

impl EffectiveSsh {
    /// A profile for `host` with every other option at its builtin default.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        let mut ssh = resolve_ssh(&SshOpts::default(), &SshOpts::default());
        ssh.host = host.into();
        ssh
    }

    /// Options that are set but whose behaviour is not implemented yet, then the ignored
    /// `~/.ssh/config` options; the session warns about each once at connect ("not supported
    /// yet: x11"). Never silently ignored.
    #[must_use]
    pub fn unsupported(&self) -> Vec<String> {
        let checks = [(
            self.input_backspace != Backspace::Backspace,
            "input_backspace",
        )];
        checks
            .into_iter()
            .filter(|(set, _)| *set)
            .map(|(_, name)| name.to_owned())
            .chain(self.ignored_ssh_config.iter().cloned())
            .collect()
    }
}

/// `profile.or(defaults).or(builtin)` for every SSH option (the SSH half of `resolve`).
#[must_use]
pub fn resolve_ssh(p: &SshOpts, d: &SshOpts) -> EffectiveSsh {
    // `profile.field` if set, else `defaults.field`.
    macro_rules! pick {
        ($field:ident) => {
            p.$field.clone().or_else(|| d.$field.clone())
        };
    }
    let ms = Duration::from_millis;
    let keepalive = pick!(keepalive_interval).unwrap_or(DEFAULT_KEEPALIVE_INTERVAL_MS);
    EffectiveSsh {
        host: pick!(host).unwrap_or_default(),
        port: pick!(port).unwrap_or(DEFAULT_SSH_PORT),
        user: pick!(user).unwrap_or_else(local_user),
        auth: pick!(auth).unwrap_or_default(),
        private_keys: pick!(private_keys).unwrap_or_default(),
        keepalive_interval: (keepalive > 0).then(|| ms(keepalive)),
        keepalive_count_max: pick!(keepalive_count_max).unwrap_or(DEFAULT_KEEPALIVE_COUNT_MAX),
        ready_timeout: pick!(ready_timeout).map(ms),
        skip_banner: pick!(skip_banner).unwrap_or(false),
        warn_on_close: pick!(warn_on_close).unwrap_or(true),
        term: pick!(term).unwrap_or_else(|| DEFAULT_TERM.to_owned()),
        input_backspace: pick!(input_backspace).unwrap_or_default(),
        jump_host: pick!(jump_host),
        proxy_command: pick!(proxy_command),
        socks_proxy: pick!(socks_proxy_host)
            .map(|host| (host, pick!(socks_proxy_port).unwrap_or(1080))),
        socks_remote_dns: pick!(socks_proxy_remote_dns).unwrap_or(true),
        http_proxy: pick!(http_proxy_host)
            .map(|host| (host, pick!(http_proxy_port).unwrap_or(8080))),
        forwarded_ports: pick!(forwarded_ports).unwrap_or_default(),
        agent_forward: pick!(agent_forward).unwrap_or(false),
        x11: pick!(x11).unwrap_or(false),
        algorithms: pick!(algorithms).unwrap_or_default(),
        reuse_session: pick!(reuse_session).unwrap_or(true),
        stored_secrets: pick!(stored_secrets).unwrap_or(true),
        reuse_linger: Duration::from_secs(
            pick!(reuse_linger).map_or(u64::from(DEFAULT_REUSE_LINGER_S), u64::from),
        ),
        scripts: pick!(scripts).unwrap_or_default(),
        cwd: pick!(cwd),
        remember_cwd: pick!(remember_cwd).unwrap_or(false),
        clear_service_messages_on_connect: pick!(clear_service_messages_on_connect).unwrap_or(true),
        verify_host_keys: pick!(verify_host_keys).unwrap_or(true),
        host_key_alias: pick!(host_key_alias),
        weight: pick!(weight).unwrap_or(0),
        identities_only: pick!(identities_only).unwrap_or(false),
        prompt_timeout: Some(pick!(prompt_timeout).unwrap_or(DEFAULT_PROMPT_TIMEOUT_MS))
            .filter(|&t| t > 0)
            .map(ms),
        agent_path: pick!(agent_path),
        agent_key_lifetime: Some(pick!(agent_key_lifetime).unwrap_or(DEFAULT_AGENT_KEY_LIFETIME_S))
            .filter(|&t| t > 0),
        ignored_ssh_config: p.ignored_ssh_config.clone(),
        jump: Jump::None,
    }
}

/// `p` with every option that resolves to the same value without it set to `None` (the
/// inverse of [`resolve_ssh`]): what the profile editor saves, so config.toml keeps only real
/// overrides. `user` (its default is the local `$USER`, which differs between machines) and
/// `osc52_write` (its default is a global setting) are kept as given.
#[must_use]
pub fn strip_ssh(p: &SshOpts, d: &SshOpts) -> SshOpts {
    let full = resolve_ssh(p, d);
    let mut out = p.clone();
    macro_rules! strip {
        ($($field:ident),* $(,)?) => {$(
            if out.$field.is_some() {
                let mut without = out.clone();
                without.$field = None;
                if resolve_ssh(&without, d) == full {
                    out = without;
                }
            }
        )*};
    }
    strip!(
        host,
        port,
        auth,
        private_keys,
        keepalive_interval,
        keepalive_count_max,
        ready_timeout,
        skip_banner,
        warn_on_close,
        term,
        input_backspace,
        jump_host,
        proxy_command,
        socks_proxy_host,
        socks_proxy_port,
        socks_proxy_remote_dns,
        http_proxy_host,
        http_proxy_port,
        forwarded_ports,
        agent_forward,
        x11,
        algorithms,
        reuse_session,
        reuse_linger,
        stored_secrets,
        scripts,
        cwd,
        remember_cwd,
        clear_service_messages_on_connect,
        verify_host_keys,
        host_key_alias,
        weight,
        identities_only,
        prompt_timeout,
        agent_path,
        agent_key_lifetime,
    );
    out
}

/// `$USER` (`%USERNAME%` on Windows), else `root`.
pub(crate) fn local_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|user| !user.is_empty())
        .unwrap_or_else(|| "root".to_owned())
}

#[cfg(test)]
#[path = "ssh_opts_tests.rs"]
mod tests;
