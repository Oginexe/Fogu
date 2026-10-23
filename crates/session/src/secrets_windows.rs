//! Stored passwords and key passphrases on Windows: the user's Credential Manager through the
//! safe `keyring` API, never a file. The public surface is identical to the Linux Secret Service
//! backend; only the storage differs.
//!
//! Failure is visible and never silent: a locked or unavailable Credential Manager is an
//! `Err(SecretError)` whose text the caller shows, and the caller asks the user instead. There
//! is no fallback storage. Secrets exist only as [`SecretString`].

#[cfg(any(test, feature = "test-store"))]
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use fogu_core::SecretKey;
use keyring::Entry;
use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret as _, SecretString};
use tokio::runtime::Handle;
use tokio::sync::OnceCell;

use crate::prompt::{PROMPT_TEXT_MAX_CHARS, sanitize_remote};

/// How long one Credential Manager call may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(15);
/// Why a stored secret could not be read, written or removed (sanitized, never a secret).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SecretError(String);

impl SecretError {
    fn new(text: impl std::fmt::Display) -> Self {
        Self(sanitize_remote(
            &text.to_string(),
            PROMPT_TEXT_MAX_CHARS,
            false,
        ))
    }
}

/// Where secrets are kept.
#[derive(Debug)]
pub enum SecretStore {
    /// The current user's Windows Credential Manager.
    Windows,
    /// No store; the text says why (shown to the user).
    Disabled(String),
    /// Tests only.
    #[cfg(any(test, feature = "test-store"))]
    InMemory(std::sync::Mutex<BTreeMap<String, SecretString>>),
}

impl SecretStore {
    /// The Credential Manager is always present on Windows; failures surface on first use.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "mirrors the Linux detect API, which is async"
    )]
    pub async fn detect() -> Self {
        Self::Windows
    }

    /// The test store.
    #[cfg(any(test, feature = "test-store"))]
    #[must_use]
    pub fn in_memory() -> Self {
        Self::InMemory(std::sync::Mutex::default())
    }

    /// The stored secret, if any.
    pub async fn get(&self, key: &SecretKey) -> Result<Option<SecretString>, SecretError> {
        match self {
            Self::Windows => match call(key, false, Entry::get_password).await {
                // Copied once into an exactly sized buffer: `SecretString::from(String)` shrinks
                // the string, and the reallocation would leave an unzeroed copy behind.
                Ok(text) => Ok(Some(SecretString::from(Zeroizing::new(text).as_str()))),
                Err(keyring::Error::NoEntry) => migrate(key).await.map_err(SecretError::new),
                Err(err) => Err(SecretError::new(err)),
            },
            Self::Disabled(reason) => Err(SecretError::new(reason)),
            #[cfg(any(test, feature = "test-store"))]
            Self::InMemory(map) => Ok(map.lock().ok().and_then(|m| m.get(&id(key)).cloned())),
        }
    }

    /// Whether a secret is stored. The Credential Manager has no lookup that leaves the secret
    /// out, so it is read and dropped at once.
    pub async fn exists(&self, key: &SecretKey) -> Result<bool, SecretError> {
        match self {
            Self::Windows => match self.get(key).await {
                Ok(Some(_)) => Ok(true),
                Ok(None) => Ok(false),
                Err(err) => Err(err),
            },
            Self::Disabled(reason) => Err(SecretError::new(reason)),
            #[cfg(any(test, feature = "test-store"))]
            Self::InMemory(map) => Ok(map.lock().is_ok_and(|m| m.contains_key(&id(key)))),
        }
    }

    /// Stores `value`, replacing what `key` held.
    pub async fn set(&self, key: &SecretKey, value: &SecretString) -> Result<(), SecretError> {
        match self {
            Self::Windows => {
                // Stays a `SecretString` (zeroed on drop) until keyring copies it out.
                let secret = value.clone();
                call(key, false, move |entry| {
                    entry.set_password(secret.expose_secret())
                })
                .await
                .map_err(SecretError::new)
            }
            Self::Disabled(reason) => Err(SecretError::new(reason)),
            #[cfg(any(test, feature = "test-store"))]
            Self::InMemory(map) => {
                if let Ok(mut map) = map.lock() {
                    map.insert(id(key), value.clone());
                }
                Ok(())
            }
        }
    }

    /// Removes the secret, under its current and its 0.1.6 name (nothing stored is not an error).
    pub async fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        match self {
            Self::Windows => {
                for legacy in [false, true] {
                    match call(key, legacy, Entry::delete_credential).await {
                        Ok(()) | Err(keyring::Error::NoEntry) => {}
                        Err(err) => return Err(SecretError::new(err)),
                    }
                }
                Ok(())
            }
            Self::Disabled(reason) => Err(SecretError::new(reason)),
            #[cfg(any(test, feature = "test-store"))]
            Self::InMemory(map) => {
                if let Ok(mut map) = map.lock() {
                    map.remove(&id(key));
                }
                Ok(())
            }
        }
    }
}

/// The Credential Manager's service name.
const SERVICE: &str = "fogu";
/// Longest user name the Credential Manager stores (`CRED_MAX_USERNAME_LENGTH` is 513; keyring
/// counts bytes).
const USER_NAME_MAX: usize = 512;

/// A stable name from the key's attributes: `fogu:name=value;…`, with `%`, `=`, `;`, upper case
/// and non-ASCII in a value percent-escaped (UTF-8 bytes) so two different keys never share a
/// name, even compared without case as the Credential Manager does. No secret is included.
fn id(key: &SecretKey) -> String {
    id_escaping(key, true)
}

/// The name 0.1.6 used: only `%`, `=` and `;` escaped, so names differing only in case collide.
/// Read once by [`migrate`] and removed by `delete`.
fn legacy_id(key: &SecretKey) -> String {
    id_escaping(key, false)
}

fn id_escaping(key: &SecretKey, case: bool) -> String {
    let mut out = String::from("fogu:");
    for (name, value) in key.attributes() {
        out.push_str(name);
        out.push('=');
        for c in value.chars() {
            match c {
                '%' | '=' | ';' => escape(&mut out, c),
                c if case && (c.is_ascii_uppercase() || !c.is_ascii()) => escape(&mut out, c),
                c => out.push(c),
            }
        }
        out.push(';');
    }
    out
}

fn escape(out: &mut String, c: char) {
    use std::fmt::Write as _;

    for byte in c.encode_utf8(&mut [0; 4]).bytes() {
        let _infallible = write!(out, "%{byte:02X}");
    }
}

/// The credential for `key`. Its target (the Credential Manager's only lookup field) is
/// `<id>.fogu`, the name earlier builds gave it, so lower-case ASCII values without `%`, `=` or
/// `;` still find what they stored. The user name is only shown in the Credential Manager: the
/// key's label, cut to the length it accepts.
fn entry(key: &SecretKey, legacy: bool) -> keyring::Result<Entry> {
    let name = if legacy { legacy_id(key) } else { id(key) };
    let target = format!("{name}.{SERVICE}");
    let mut user = key.label();
    if user.len() > USER_NAME_MAX {
        let mut end = USER_NAME_MAX;
        while !user.is_char_boundary(end) {
            end -= 1;
        }
        user.truncate(end);
    }
    Entry::new_with_target(&target, SERVICE, &user)
}

/// Runs one blocking Credential Manager call on the blocking pool. A task that fails or does not
/// answer in time is a `PlatformFailure`, so callers match only on keyring's own variants.
async fn call<T: Send + 'static>(
    key: &SecretKey,
    legacy: bool,
    operation: impl FnOnce(&Entry) -> keyring::Result<T> + Send + 'static,
) -> keyring::Result<T> {
    let key = key.clone();
    let task = tokio::task::spawn_blocking(move || operation(&entry(&key, legacy)?));
    let failure = match tokio::time::timeout(CALL_TIMEOUT, task).await {
        Ok(Ok(result)) => return result,
        Ok(Err(err)) => format!("Credential Manager task failed: {err}"),
        Err(_elapsed) => "Credential Manager did not answer in time".to_owned(),
    };
    Err(keyring::Error::PlatformFailure(failure.into()))
}

/// A secret 0.1.6 stored under [`legacy_id`], moved to the current name so it is found again
/// and the old entry does not linger. `None` when there is none.
async fn migrate(key: &SecretKey) -> keyring::Result<Option<SecretString>> {
    if legacy_id(key) == id(key) {
        return Ok(None);
    }
    let secret = match call(key, true, Entry::get_password).await {
        Ok(text) => SecretString::from(Zeroizing::new(text).as_str()),
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(err) => return Err(err),
    };
    let value = secret.clone();
    call(key, false, move |entry| {
        entry.set_password(value.expose_secret())
    })
    .await?;
    call(key, true, Entry::delete_credential).await?;
    Ok(Some(secret))
}

/// The session runtime's secret store: connected on first use, called on the session runtime.
#[derive(Clone, Debug)]
pub struct Secrets {
    rt: Handle,
    store: Arc<OnceCell<SecretStore>>,
}

impl Secrets {
    /// The Windows Credential Manager, used when first needed.
    #[must_use]
    pub fn new(rt: Handle) -> Self {
        Self {
            rt,
            store: Arc::new(OnceCell::new()),
        }
    }

    /// A fixed `store` (tests, `Disabled`).
    #[must_use]
    pub fn with_store(rt: Handle, store: SecretStore) -> Self {
        Self {
            rt,
            store: Arc::new(OnceCell::new_with(Some(store))),
        }
    }

    /// Runs `fut` on the session runtime, whichever executor awaits the result.
    async fn spawn<T: Send + 'static>(
        &self,
        fut: impl Future<Output = Result<T, SecretError>> + Send + 'static,
    ) -> Result<T, SecretError> {
        self.rt
            .spawn(fut)
            .await
            .unwrap_or_else(|_| Err(SecretError::new("the secret store task failed")))
    }

    /// See [`SecretStore::get`].
    pub async fn get(&self, key: &SecretKey) -> Result<Option<SecretString>, SecretError> {
        let (store, key) = (Arc::clone(&self.store), key.clone());
        let fut = async move { store.get_or_init(SecretStore::detect).await.get(&key).await };
        self.spawn(fut).await
    }

    /// See [`SecretStore::exists`].
    pub async fn exists(&self, key: &SecretKey) -> Result<bool, SecretError> {
        let (store, key) = (Arc::clone(&self.store), key.clone());
        let fut = async move {
            store
                .get_or_init(SecretStore::detect)
                .await
                .exists(&key)
                .await
        };
        self.spawn(fut).await
    }

    /// See [`SecretStore::set`].
    pub async fn set(&self, key: &SecretKey, value: SecretString) -> Result<(), SecretError> {
        let (store, key) = (Arc::clone(&self.store), key.clone());
        let fut = async move {
            let store = store.get_or_init(SecretStore::detect).await;
            store.set(&key, &value).await
        };
        self.spawn(fut).await
    }

    /// See [`SecretStore::delete`].
    pub async fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        let (store, key) = (Arc::clone(&self.store), key.clone());
        let fut = async move {
            store
                .get_or_init(SecretStore::detect)
                .await
                .delete(&key)
                .await
        };
        self.spawn(fut).await
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn key(user: &str) -> SecretKey {
        SecretKey::SshPassword {
            user: user.into(),
            host: "h".into(),
            port: 22,
        }
    }

    #[tokio::test]
    async fn in_memory_round_trip_and_disabled_errors() {
        let store = SecretStore::in_memory();
        assert!(
            store
                .get(&key("a"))
                .await
                .unwrap()
                .map(|s| s.expose_secret().to_owned())
                .is_none()
        );
        store
            .set(&key("a"), &SecretString::from("one"))
            .await
            .unwrap();
        store
            .set(&key("a"), &SecretString::from("two"))
            .await
            .unwrap();
        assert!(store.exists(&key("a")).await.unwrap());
        assert!(!store.exists(&key("b")).await.unwrap());
        assert_eq!(
            store.get(&key("a")).await.unwrap().unwrap().expose_secret(),
            "two"
        );
        store.delete(&key("a")).await.unwrap();
        assert!(!store.exists(&key("a")).await.unwrap());

        let off = SecretStore::Disabled("no store".into());
        assert_eq!(
            off.get(&key("a")).await.unwrap_err().to_string(),
            "no store"
        );
    }

    #[test]
    fn ids_are_stable_and_never_contain_a_secret() {
        let a = id(&key("alice"));
        let b = id(&key("alice"));
        assert_eq!(a, b);
        assert!(a.starts_with("fogu:"));
        assert!(!a.contains("hunter2"));
        assert_ne!(a, id(&key("bob")));
    }

    #[test]
    fn separators_in_a_value_never_make_two_keys_share_an_id() {
        let tricky = SecretKey::SshPassword {
            user: "a;host=x".into(),
            host: "h".into(),
            port: 22,
        };
        assert_ne!(id(&tricky), id(&key("a")));
        assert!(id(&tricky).contains("user=a%3Bhost%3Dx;"));
        // A plain value keeps the name earlier builds stored it under.
        assert!(id(&key("alice")).contains("user=alice;"));
    }

    /// Against the real Credential Manager (Windows CI): a 0.1.6 entry is found, moved to the new
    /// name, and gone from the old one; `delete` leaves nothing.
    #[tokio::test]
    async fn a_secret_stored_by_0_1_6_is_moved_to_the_new_name() {
        let key = key(&format!("Fogu-Migrate-{}", std::process::id()));
        entry(&key, true).unwrap().set_password("hunter2").unwrap();
        let store = SecretStore::Windows;
        let got = store.get(&key).await.unwrap().unwrap();
        assert_eq!(got.expose_secret(), "hunter2");
        assert!(matches!(
            entry(&key, true).unwrap().get_password(),
            Err(keyring::Error::NoEntry)
        ));
        assert_eq!(
            entry(&key, false).unwrap().get_password().unwrap(),
            "hunter2"
        );
        store.delete(&key).await.unwrap();
        assert!(!store.exists(&key).await.unwrap());
    }

    #[test]
    fn the_legacy_name_is_only_needed_for_upper_case_or_non_ascii() {
        assert_eq!(legacy_id(&key("alice")), id(&key("alice")));
        assert_eq!(
            legacy_id(&key("Alice")),
            id(&key("alice")).replace("alice", "Alice")
        );
        assert_ne!(legacy_id(&key("Alice")), id(&key("Alice")));
    }

    #[test]
    fn ids_differ_even_ignoring_case() {
        // The Credential Manager compares target names without case.
        let folded = |user: &str| id(&key(user)).to_lowercase();
        assert_ne!(folded("Alice"), folded("alice"));
        assert_ne!(folded("\u{c9}"), folded("\u{e9}"));
    }

    #[test]
    fn a_long_login_script_key_still_makes_an_entry() {
        let long = SecretKey::LoginScript {
            profile_id: fogu_core::ProfileId("p".repeat(400)),
            name: "n".repeat(400),
        };
        entry(&long, false).unwrap();
    }
}
