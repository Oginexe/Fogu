//! Authentication order:
//! `none` → agent identities (those whose `.pub` sits next to a configured key first) → private
//! key files (passphrase prompt for encrypted ones; OpenSSH/PEM/PKCS#8/PuTTY) → password prompt →
//! keyboard-interactive (prompts forwarded with their echo flags), filtered by the profile's
//! `auth`. Methods the server no longer lists are skipped; a failing method is logged and the
//! next one tried; all failed → `SessionError::AuthFailed`.
//!
//! Secrets: passwords, passphrases, answers and key-file text are `SecretString`s, exposed only
//! as the argument of the russh / key-decoding call. russh copies a password into its own
//! `String` for the packet (not zeroized; outside our control).
//!
//! Stored secrets: a password / key passphrase the Secret Service holds is tried once per
//! connection before the prompt. One the server (or the key) refuses is never retried: the user
//! is asked, and the dialog offers to replace or forget it. A prompt's secret is stored only
//! after it proved right (the server accepted the password; the key decrypted). A store that
//! is missing or locked is reported in the terminal and the user is asked as before.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fogu_core::{EffectiveSsh, SecretKey, SshAuth};
use russh::client::KeyboardInteractiveAuthResponse as Kbd;
use russh::keys::agent::{AgentIdentity, Constraint};
use russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::{MethodKind, MethodSet, client::AuthResult};
use secrecy::{ExposeSecret as _, SecretString};

use super::agent::{self, Agent};
use super::connect::{Connection, ssh_error};
use super::hostkeys::fingerprint;
use super::{Stop, Ui};
use crate::prompt::{
    KbdPrompt, PROMPT_INSTRUCTIONS_MAX_CHARS, PROMPT_MAX_COUNT, PROMPT_TEXT_MAX_CHARS,
    sanitize_remote,
};
use crate::secrets::SecretError;
use crate::{PromptKind, PromptReply, Remember, SessionError, SessionOutput, SessionWarning};

/// One step of the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    None,
    Agent,
    PublicKey,
    Password,
    KeyboardInteractive,
}

/// Password prompts per connection (OpenSSH's `NumberOfPasswordPrompts`).
const PASSWORD_ATTEMPTS: usize = 3;
/// Passphrase prompts per key file.
const PASSPHRASE_ATTEMPTS: usize = 3;
/// Keyboard-interactive rounds before giving up on the method (a hostile server could loop).
const KBD_MAX_ROUNDS: usize = 10;
/// Private key files larger than this are not read.
const MAX_KEY_FILE_BYTES: u64 = 1024 * 1024;
/// Tried when a profile names no key file, in OpenSSH's order (`man ssh`, `-i`).
const DEFAULT_IDENTITIES: [&str; 5] = [
    "~/.ssh/id_rsa",
    "~/.ssh/id_ecdsa",
    "~/.ssh/id_ecdsa_sk",
    "~/.ssh/id_ed25519",
    "~/.ssh/id_ed25519_sk",
];

/// The methods tried for `auth`, in order.
pub(crate) fn plan(auth: SshAuth) -> &'static [Method] {
    use Method::{Agent, KeyboardInteractive, None, Password, PublicKey};
    match auth {
        SshAuth::Auto => &[None, Agent, PublicKey, Password, KeyboardInteractive],
        SshAuth::Password => &[None, Password],
        SshAuth::PublicKey => &[None, PublicKey],
        SshAuth::Agent => &[None, Agent],
        SshAuth::KeyboardInteractive => &[None, KeyboardInteractive],
    }
}

/// The protocol method behind a step (`None` is always attempted).
fn kind(method: Method) -> Option<MethodKind> {
    match method {
        Method::None => None,
        Method::Agent | Method::PublicKey => Some(MethodKind::PublicKey),
        Method::Password => Some(MethodKind::Password),
        Method::KeyboardInteractive => Some(MethodKind::KeyboardInteractive),
    }
}

/// `false` when the server's last failure response no longer lists `method`.
pub(crate) fn server_allows(allowed: Option<&MethodSet>, method: Method) -> bool {
    match (allowed, kind(method)) {
        (Some(set), Some(kind)) if !set.is_empty() => set.contains(&kind),
        _ => true,
    }
}

enum Outcome {
    Success,
    /// Failed; the server's remaining methods (may be empty).
    Failure(MethodSet),
    /// Not attempted (no agent, no keys, user declined).
    Skipped,
}

impl From<AuthResult> for Outcome {
    fn from(result: AuthResult) -> Self {
        match result {
            AuthResult::Success => Self::Success,
            AuthResult::Failure {
                remaining_methods, ..
            } => Self::Failure(remaining_methods),
        }
    }
}

/// Context for one authentication run.
struct Auth<'a> {
    conn: &'a mut Connection,
    ssh: &'a EffectiveSsh,
    ui: &'a mut Ui,
    ready: Duration,
    /// Why stored secrets cannot be used on this connection (reported once).
    store_problem: Option<String>,
}

/// Runs the plan until one method succeeds.
pub(crate) async fn authenticate(
    conn: &mut Connection,
    ssh: &EffectiveSsh,
    ui: &mut Ui,
    ready: Duration,
) -> Result<(), Stop> {
    let mut auth = Auth {
        conn,
        ssh,
        ui,
        ready,
        store_problem: (!ssh.stored_secrets)
            .then(|| "turned off for this profile (stored_secrets = false)".to_owned()),
    };
    let mut allowed: Option<MethodSet> = None;
    for &method in plan(ssh.auth) {
        if !server_allows(allowed.as_ref(), method) {
            tracing::debug!(?method, "skipped: not offered by the server");
            continue;
        }
        let outcome = match method {
            Method::None => auth.none().await?,
            Method::Agent => auth.agent().await?,
            Method::PublicKey => auth.keys().await?,
            Method::Password => auth.password(&mut allowed).await?,
            Method::KeyboardInteractive => auth.keyboard_interactive().await?,
        };
        auth.conn.drain_events(ssh, auth.ui).await?;
        match outcome {
            Outcome::Success => {
                tracing::info!(?method, "authenticated");
                return Ok(());
            }
            Outcome::Failure(remaining) => {
                tracing::info!(?method, "authentication method failed");
                if !remaining.is_empty() {
                    allowed = Some(remaining);
                }
            }
            Outcome::Skipped => {}
        }
    }
    Err(SessionError::AuthFailed.into())
}

/// Awaits a russh call under `ready_timeout`.
async fn call<T, E: std::fmt::Display>(
    ready: Duration,
    fut: impl Future<Output = Result<T, E>>,
) -> Result<T, Stop> {
    match tokio::time::timeout(ready, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(ssh_error(&err).into()),
        Err(_elapsed) => Err(SessionError::Timeout.into()),
    }
}

impl Auth<'_> {
    async fn none(&mut self) -> Result<Outcome, Stop> {
        let user = self.ssh.user.clone();
        let fut = self.conn.handle.authenticate_none(user);
        Ok(call(self.ready, fut).await?.into())
    }

    /// RSA keys are signed by an OpenSSH agent only (the `rsa` crate is not built in:
    /// RUSTSEC-2023-0071, non-constant-time private-key operations, no fixed release). Without
    /// any agent the key is skipped visibly.
    async fn refuse_rsa(&mut self, path: &Path) -> Result<Outcome, Stop> {
        tracing::warn!(path = %path.display(), "RSA key skipped: no SSH agent");
        self.ui
            .service(&format!(
                "Skipping RSA key {}: RSA keys need an SSH agent and ssh-agent could not be \
                 started (install openssh, or use an ed25519 key)",
                path.display()
            ))
            .await?;
        Ok(Outcome::Skipped)
    }

    /// The RSA signature hash the server accepts (`None` = legacy `ssh-rsa`).
    async fn rsa_hash(&self, algorithm: &Algorithm) -> Result<Option<HashAlg>, Stop> {
        if !matches!(algorithm, Algorithm::Rsa { .. }) {
            return Ok(None);
        }
        Ok(call(self.ready, self.conn.handle.best_supported_rsa_hash())
            .await?
            .flatten())
    }

    async fn agent(&mut self) -> Result<Outcome, Stop> {
        let configured = self.ssh.agent_path.as_deref().map(expand_home);
        let Some(mut agent) = agent::connect(configured.as_deref()).await else {
            tracing::debug!("no SSH agent");
            return Ok(Outcome::Skipped);
        };
        let identities = match call(self.ready, agent.request_identities()).await {
            Ok(ids) => ids,
            Err(Stop::Failed(err)) => {
                tracing::warn!(error = %err, "SSH agent: listing identities failed");
                return Ok(Outcome::Skipped);
            }
            Err(stop) => return Err(stop),
        };
        let preferred = configured_public_keys(&self.key_paths());
        let mut keys: Vec<PublicKey> = identities
            .into_iter()
            .filter_map(|id| match id {
                AgentIdentity::PublicKey { key, .. } => Some(key),
                AgentIdentity::Certificate { .. } => None,
            })
            .collect();
        let is_configured =
            |key: &PublicKey| preferred.iter().any(|p| p.key_data() == key.key_data());
        if self.ssh.identities_only {
            keys.retain(is_configured);
        }
        keys.sort_by_key(|key| !is_configured(key));
        let mut last = Outcome::Skipped;
        for key in keys {
            match self.with_agent(&mut agent, key).await? {
                Outcome::Success => return Ok(Outcome::Success),
                Outcome::Skipped => {}
                failure @ Outcome::Failure(_) => last = failure,
            }
        }
        Ok(last)
    }

    /// One public-key attempt signed by `agent`.
    async fn with_agent(&mut self, agent: &mut Agent, key: PublicKey) -> Result<Outcome, Stop> {
        self.ui
            .service(&format!("Trying agent key {}", fingerprint(&key)))
            .await?;
        let hash = self.rsa_hash(&key.algorithm()).await?;
        let user = self.ssh.user.clone();
        let fut = self
            .conn
            .handle
            .authenticate_publickey_with(user, key, hash, agent);
        match tokio::time::timeout(self.ready, fut).await {
            Ok(Ok(result)) => Ok(result.into()),
            Ok(Err(err)) => {
                tracing::warn!(error = %ssh_error(&err), "SSH agent signing failed");
                Ok(Outcome::Skipped)
            }
            Err(_elapsed) => Err(SessionError::Timeout.into()),
        }
    }

    /// The profile's key files, else OpenSSH's default identities that exist.
    fn key_paths(&self) -> Vec<PathBuf> {
        if !self.ssh.private_keys.is_empty() {
            return self
                .ssh
                .private_keys
                .iter()
                .map(|p| expand_home(p))
                .collect();
        }
        DEFAULT_IDENTITIES
            .iter()
            .map(|p| expand_home(Path::new(p)))
            .filter(|p| p.is_file())
            .collect()
    }

    /// An RSA key file: used from the agent when it already holds it (no passphrase), else
    /// decoded here (passphrase prompt), added to the agent with the profile's lifetime, and
    /// signed by the agent. Fogu only decrypts the file, never signs with RSA itself.
    async fn rsa_key(&mut self, path: &Path, public: Option<PublicKey>) -> Result<Outcome, Stop> {
        let configured = self.ssh.agent_path.as_deref().map(expand_home);
        let Some(mut agent) = agent::connect_or_start(configured.as_deref()).await else {
            return self.refuse_rsa(path).await;
        };
        if let Some(public) = public {
            let held = call(self.ready, agent.request_identities()).await?;
            if held.iter().any(|id| match id {
                AgentIdentity::PublicKey { key, .. } => key.key_data() == public.key_data(),
                AgentIdentity::Certificate { .. } => false,
            }) {
                return self.with_agent(&mut agent, public).await;
            }
        }
        let Some(key) = self.load_key(path).await? else {
            return Ok(Outcome::Skipped);
        };
        self.add_and_sign(&mut agent, path, key).await
    }

    /// An RSA key decoded here from a non-OpenSSH file.
    async fn rsa_decoded(&mut self, path: &Path, key: PrivateKey) -> Result<Outcome, Stop> {
        let configured = self.ssh.agent_path.as_deref().map(expand_home);
        let Some(mut agent) = agent::connect_or_start(configured.as_deref()).await else {
            return self.refuse_rsa(path).await;
        };
        self.add_and_sign(&mut agent, path, key).await
    }

    /// Adds `key` to `agent` (with the lifetime constraint) and authenticates with it there.
    async fn add_and_sign(
        &mut self,
        agent: &mut Agent,
        path: &Path,
        key: PrivateKey,
    ) -> Result<Outcome, Stop> {
        let constraints: Vec<Constraint> = self
            .ssh
            .agent_key_lifetime
            .map(|seconds| Constraint::KeyLifetime { seconds })
            .into_iter()
            .collect();
        if let Err(err) = call(self.ready, agent.add_identity(&key, &constraints)).await {
            tracing::warn!(path = %path.display(), "adding the RSA key to the agent failed");
            self.ui
                .service(&format!("SSH agent refused key {}", path.display()))
                .await?;
            return match err {
                Stop::Failed(_) => Ok(Outcome::Skipped),
                stop => Err(stop),
            };
        }
        let public = key.public_key().clone();
        drop(key);
        self.with_agent(agent, public).await
    }

    async fn keys(&mut self) -> Result<Outcome, Stop> {
        let mut last = Outcome::Skipped;
        for path in self.key_paths() {
            let public = openssh_public_key(&path);
            if public.as_ref().is_some_and(|k| is_rsa(&k.algorithm())) {
                match self.rsa_key(&path, public).await? {
                    Outcome::Success => return Ok(Outcome::Success),
                    Outcome::Skipped => {}
                    failure @ Outcome::Failure(_) => last = failure,
                }
                continue;
            }
            let Some(key) = self.load_key(&path).await? else {
                continue;
            };
            if is_rsa(&key.algorithm()) {
                // PEM / PKCS#8 / PuTTY RSA: the public half shows only after decoding.
                match self.rsa_decoded(&path, key).await? {
                    Outcome::Success => return Ok(Outcome::Success),
                    Outcome::Skipped => {}
                    failure @ Outcome::Failure(_) => last = failure,
                }
                continue;
            }
            self.ui
                .service(&format!("Trying private key {}", path.display()))
                .await?;
            let hash = self.rsa_hash(&key.algorithm()).await?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
            let user = self.ssh.user.clone();
            let result = call(
                self.ready,
                self.conn.handle.authenticate_publickey(user, key),
            )
            .await?;
            match Outcome::from(result) {
                Outcome::Success => return Ok(Outcome::Success),
                failure => last = failure,
            }
        }
        Ok(last)
    }

    /// Reads and decodes a key file, prompting for its passphrase when it is encrypted.
    /// `None` = skip this key (unreadable, wrong passphrase, declined).
    async fn load_key(&mut self, path: &Path) -> Result<Option<PrivateKey>, Stop> {
        let text = match read_key_file(path) {
            Ok(text) => text,
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "private key unreadable");
                self.ui
                    .service(&format!(
                        "Cannot read private key {}: {err}",
                        path.display()
                    ))
                    .await?;
                return Ok(None);
            }
        };
        let first = russh::keys::decode_secret_key(text.expose_secret(), None);
        let err = match first {
            Ok(key) => return Ok(Some(key)),
            Err(err) if needs_passphrase(text.expose_secret(), &err) => err,
            Err(err) => {
                self.ui
                    .service(&format!(
                        "Cannot load private key {}: {err}",
                        path.display()
                    ))
                    .await?;
                return Ok(None);
            }
        };
        tracing::debug!(path = %path.display(), error = %err, "key is encrypted");
        Box::pin(self.passphrase(path, &text)).await
    }

    /// The stored passphrase of an encrypted key (tried once), else prompts.
    async fn passphrase(
        &mut self,
        path: &Path,
        text: &SecretString,
    ) -> Result<Option<PrivateKey>, Stop> {
        let key = SecretKey::KeyPassphrase {
            key_fingerprint: file_fingerprint(text),
        };
        let mut rejected = false;
        if let Some(stored) = self.stored(&key).await? {
            let decoded =
                russh::keys::decode_secret_key(text.expose_secret(), Some(stored.expose_secret()));
            if let Ok(key) = decoded {
                let line = format!("Using the stored passphrase for {}", path.display());
                self.ui.service(&line).await?;
                return Ok(Some(key));
            }
            let line = format!("Stored passphrase for {} rejected", path.display());
            self.ui.service(&line).await?;
            rejected = true;
        }
        let mut asked = 0;
        while asked < PASSPHRASE_ATTEMPTS {
            let kind = PromptKind::KeyPassphrase {
                path: path.to_path_buf(),
                remember: self.remember(rejected),
            };
            let (passphrase, save) = match self.ui.ask(kind).await? {
                PromptReply::Secret { value, remember } => (value, remember),
                PromptReply::Forget => {
                    self.forget(&key, "passphrase").await?;
                    rejected = false;
                    continue;
                }
                _ => return Ok(None),
            };
            asked += 1;
            match russh::keys::decode_secret_key(
                text.expose_secret(),
                Some(passphrase.expose_secret()),
            ) {
                Ok(decoded) => {
                    if save {
                        self.save(&key, passphrase, "passphrase").await?;
                    }
                    return Ok(Some(decoded));
                }
                Err(_) => self.ui.service("Wrong passphrase").await?,
            }
        }
        Ok(None)
    }

    /// `Remember` for the next prompt; `rejected` = a stored secret was just refused.
    fn remember(&self, rejected: bool) -> Remember {
        match (&self.store_problem, rejected) {
            (Some(why), _) => Remember::Unavailable(why.clone()),
            (None, true) => Remember::Rejected,
            (None, false) => Remember::Available,
        }
    }

    /// Says (once) that stored secrets can't be used here; the user is asked instead.
    async fn store_failed(&mut self, err: &SecretError) -> Result<(), Stop> {
        tracing::warn!(error = %err, "stored secrets unavailable");
        self.store_problem = Some(err.to_string());
        self.store_notice(format!("Stored secrets unavailable: {err}"))
            .await
    }

    /// A store problem the user should see: a terminal line (the profile may clear those on
    /// connect) and a warning (toast + tab badge).
    async fn store_notice(&mut self, text: String) -> Result<(), Stop> {
        self.ui.service(&text).await?;
        self.ui
            .pump
            .emit(SessionOutput::Warning(SessionWarning::SecretStore(text)))
            .await?;
        Ok(())
    }

    /// The stored secret for `key`; none when there is none or the store is unusable.
    async fn stored(&mut self, key: &SecretKey) -> Result<Option<SecretString>, Stop> {
        if self.store_problem.is_some() {
            return Ok(None);
        }
        match self.ui.secrets.get(key).await {
            Ok(found) => Ok(found),
            Err(err) => {
                self.store_failed(&err).await?;
                Ok(None)
            }
        }
    }

    /// Stores a secret that proved right; failure is shown, never fatal.
    async fn save(&mut self, key: &SecretKey, value: SecretString, what: &str) -> Result<(), Stop> {
        if self.store_problem.is_some() {
            return Ok(());
        }
        match self.ui.secrets.set(key, value).await {
            Ok(()) => {
                let line = format!("Saved the {what} to the Secret Service");
                self.ui.service(&line).await?;
            }
            Err(err) => {
                self.store_notice(format!("Could not save the {what}: {err}"))
                    .await?;
            }
        }
        Ok(())
    }

    /// Deletes a rejected stored secret (the user chose Forget).
    async fn forget(&mut self, key: &SecretKey, what: &str) -> Result<(), Stop> {
        match self.ui.secrets.delete(key).await {
            Ok(()) => {
                let line = format!("Forgot the stored {what}");
                self.ui.service(&line).await?;
            }
            Err(err) => {
                self.store_notice(format!("Could not forget the stored {what}: {err}"))
                    .await?;
            }
        }
        Ok(())
    }

    /// One password attempt.
    async fn try_password(&mut self, password: &SecretString) -> Result<Outcome, Stop> {
        let user = self.ssh.user.clone();
        let fut = self
            .conn
            .handle
            .authenticate_password(user, password.expose_secret());
        Ok(call(self.ready, fut).await?.into())
    }

    async fn password(&mut self, allowed: &mut Option<MethodSet>) -> Result<Outcome, Stop> {
        let key = SecretKey::ssh_password(self.ssh);
        let mut last = Outcome::Skipped;
        let mut rejected = false;
        if let Some(stored) = self.stored(&key).await? {
            self.ui.service("Using the stored password").await?;
            match self.try_password(&stored).await? {
                Outcome::Success => return Ok(Outcome::Success),
                Outcome::Failure(remaining) => {
                    self.ui.service("Stored password rejected").await?;
                    if !remaining.is_empty() {
                        *allowed = Some(remaining.clone());
                    }
                    last = Outcome::Failure(remaining);
                    rejected = true;
                }
                Outcome::Skipped => {}
            }
        }
        let mut asked = 0;
        while asked < PASSWORD_ATTEMPTS && server_allows(allowed.as_ref(), Method::Password) {
            let kind = PromptKind::Password {
                user: self.ssh.user.clone(),
                host: self.ssh.host.clone(),
                remember: self.remember(rejected),
            };
            let (password, save) = match self.ui.ask(kind).await? {
                PromptReply::Secret { value, remember } => (value, remember),
                PromptReply::Forget => {
                    self.forget(&key, "password").await?;
                    rejected = false;
                    continue;
                }
                _ => return Ok(Outcome::Skipped),
            };
            asked += 1;
            match self.try_password(&password).await? {
                Outcome::Success => {
                    if save {
                        self.save(&key, password, "password").await?;
                    }
                    return Ok(Outcome::Success);
                }
                Outcome::Failure(remaining) => {
                    self.ui.service("Password rejected").await?;
                    if !remaining.is_empty() {
                        *allowed = Some(remaining.clone());
                    }
                    last = Outcome::Failure(remaining);
                }
                Outcome::Skipped => {}
            }
        }
        Ok(last)
    }

    async fn keyboard_interactive(&mut self) -> Result<Outcome, Stop> {
        let user = self.ssh.user.clone();
        let fut = self
            .conn
            .handle
            .authenticate_keyboard_interactive_start(user, None);
        let mut response = call(self.ready, fut).await?;
        for _ in 0..KBD_MAX_ROUNDS {
            let (name, instructions, prompts) = match response {
                Kbd::Success => return Ok(Outcome::Success),
                Kbd::Failure {
                    remaining_methods, ..
                } => return Ok(Outcome::Failure(remaining_methods)),
                Kbd::InfoRequest {
                    name,
                    instructions,
                    prompts,
                } => (name, instructions, prompts),
            };
            if prompts.len() > PROMPT_MAX_COUNT {
                tracing::warn!(
                    count = prompts.len(),
                    "too many keyboard-interactive prompts"
                );
                return Ok(Outcome::Failure(MethodSet::empty()));
            }
            let answers: Vec<String> = if prompts.is_empty() {
                Vec::new()
            } else {
                let kind = kbd_prompt(&name, &instructions, &prompts);
                match self.ui.ask(kind).await? {
                    PromptReply::Secrets(answers) if answers.len() == prompts.len() => answers
                        .iter()
                        .map(|a| a.expose_secret().to_owned())
                        .collect(),
                    _ => return Ok(Outcome::Skipped),
                }
            };
            let fut = self
                .conn
                .handle
                .authenticate_keyboard_interactive_respond(answers);
            response = call(self.ready, fut).await?;
        }
        Ok(Outcome::Failure(MethodSet::empty()))
    }
}

/// The UI prompt for one keyboard-interactive round, server texts sanitized and capped.
fn kbd_prompt(name: &str, instructions: &str, prompts: &[russh::client::Prompt]) -> PromptKind {
    PromptKind::KeyboardInteractive {
        name: sanitize_remote(name, PROMPT_TEXT_MAX_CHARS, false),
        instructions: sanitize_remote(instructions, PROMPT_INSTRUCTIONS_MAX_CHARS, true),
        prompts: prompts
            .iter()
            .map(|p| KbdPrompt {
                text: sanitize_remote(&p.prompt, PROMPT_TEXT_MAX_CHARS, false),
                echo: p.echo,
            })
            .collect(),
    }
}

/// `~/x` → `$HOME/x`.
fn expand_home(path: &Path) -> PathBuf {
    match (path.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => path.to_path_buf(),
    }
}

/// Public halves (`<key>.pub`) of the configured keys, for agent identity ordering.
fn configured_public_keys(keys: &[PathBuf]) -> Vec<PublicKey> {
    keys.iter()
        .filter_map(|path| {
            let path = expand_home(path);
            let pub_path = if path.extension().is_some_and(|e| e == "pub") {
                path
            } else {
                let mut name = path.into_os_string();
                name.push(".pub");
                PathBuf::from(name)
            };
            russh::keys::load_public_key(&pub_path).ok()
        })
        .collect()
}

/// The unencrypted public half of an OpenSSH private key file (readable without the passphrase).
fn openssh_public_key(path: &Path) -> Option<PublicKey> {
    let text = read_key_file(path).ok()?;
    russh::keys::ssh_key::PrivateKey::from_openssh(text.expose_secret())
        .ok()
        .map(|key| key.public_key().clone())
}

/// What a key's stored passphrase is filed under: the public key's SHA-256 fingerprint (the
/// public half is readable without the passphrase), else a SHA-256 of the file text.
fn file_fingerprint(text: &SecretString) -> String {
    use std::fmt::Write as _;
    if let Ok(key) = russh::keys::ssh_key::PrivateKey::from_openssh(text.expose_secret()) {
        return fingerprint(key.public_key());
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, text.expose_secret().as_bytes());
    let mut hex = String::from("file:sha256:");
    for byte in digest.as_ref() {
        let _infallible = write!(hex, "{byte:02x}");
    }
    hex
}

/// [`file_fingerprint`] of the key file at `path` (`~` expanded; `None` = unreadable); the profile editor files
/// a key's passphrase under the same name the connection looks it up by.
#[must_use]
pub fn key_fingerprint(path: &Path) -> Option<String> {
    let text = read_key_file(&expand_home(path)).ok()?;
    Some(file_fingerprint(&text))
}

/// A key file's text, as a secret (it may be an unencrypted private key).
fn read_key_file(path: &Path) -> std::io::Result<SecretString> {
    let file = std::fs::File::open(path)?;
    let mut text = String::new();
    file.take(MAX_KEY_FILE_BYTES).read_to_string(&mut text)?;
    Ok(SecretString::from(text))
}

/// Whether a failed passphrase-less decode means "encrypted": russh says so for OpenSSH/PEM;
/// encrypted PKCS#8 and `PuTTY` files are recognised by their headers.
fn is_rsa(algorithm: &Algorithm) -> bool {
    matches!(algorithm, Algorithm::Rsa { .. })
}

fn needs_passphrase(text: &str, err: &russh::keys::Error) -> bool {
    matches!(err, russh::keys::Error::KeyIsEncrypted)
        || text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || (text.trim_start().starts_with("PuTTY-User-Key-File-")
            && text
                .lines()
                .any(|l| l.starts_with("Encryption:") && !l.ends_with("none")))
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
