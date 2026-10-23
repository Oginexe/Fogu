//! What a stored secret is for. A [`SecretKey`] names a secret in the
//! desktop Secret Service: its [`attributes`](SecretKey::attributes) are the lookup key and its
//! [`label`](SecretKey::label) the human-readable title. Neither ever holds the secret itself.

use std::collections::BTreeMap;

use crate::{EffectiveSsh, ProfileId};

/// Value of the `application` attribute on every item we store.
pub const APPLICATION: &str = "fogu";
/// The SSH port, left out of labels.
const DEFAULT_PORT: u16 = 22;

/// One stored secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretKey {
    /// The key that encrypts SSH scrollback saved for tab recovery.
    RecoveryKey,
    /// The password of `user@host:port`.
    SshPassword {
        /// Remote user.
        user: String,
        /// Host as configured (compared case-insensitively).
        host: String,
        /// SSH port.
        port: u16,
    },
    /// The passphrase of an encrypted private key.
    KeyPassphrase {
        /// SHA-256 of the key's public half, or of the file when that is unreadable (hex).
        key_fingerprint: String,
    },
    /// An answer a login script types.
    LoginScript {
        /// The profile that owns the script.
        profile_id: ProfileId,
        /// The script entry's name.
        name: String,
    },
}

impl SecretKey {
    /// The password of the account `ssh` connects to (what the connection and the profile
    /// editor both look up).
    #[must_use]
    pub fn ssh_password(ssh: &EffectiveSsh) -> Self {
        Self::SshPassword {
            user: ssh.user.clone(),
            host: ssh.host.clone(),
            port: ssh.port,
        }
    }

    /// The Secret Service lookup attributes: `application=fogu`, `kind=…`, plus the fields.
    #[must_use]
    pub fn attributes(&self) -> BTreeMap<&'static str, String> {
        let mut map = BTreeMap::from([("application", APPLICATION.to_owned())]);
        match self {
            Self::RecoveryKey => {
                map.insert("kind", "recovery-key".to_owned());
            }
            Self::SshPassword { user, host, port } => {
                map.insert("kind", "ssh-password".to_owned());
                map.insert("user", user.clone());
                map.insert("host", host.to_ascii_lowercase());
                map.insert("port", port.to_string());
            }
            Self::KeyPassphrase { key_fingerprint } => {
                map.insert("kind", "key-passphrase".to_owned());
                map.insert("key_fingerprint", key_fingerprint.clone());
            }
            Self::LoginScript { profile_id, name } => {
                map.insert("kind", "login-script".to_owned());
                map.insert("profile", profile_id.0.clone());
                map.insert("name", name.clone());
            }
        }
        map
    }

    /// The item's title in the user's keyring tool. Never contains a secret.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::RecoveryKey => "Fogu SSH scrollback recovery key".to_owned(),
            Self::SshPassword { user, host, port } if *port == DEFAULT_PORT => {
                format!("Fogu SSH password for {user}@{host}")
            }
            Self::SshPassword { user, host, port } => {
                format!("Fogu SSH password for {user}@{host}:{port}")
            }
            Self::KeyPassphrase { key_fingerprint } => {
                let short: String = key_fingerprint.chars().take(12).collect();
                format!("Fogu SSH key passphrase ({short})")
            }
            Self::LoginScript { profile_id, name } => {
                format!("Fogu login script answer ({}: {name})", profile_id.0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(k: &SecretKey) -> Vec<(&'static str, String)> {
        k.attributes().into_iter().collect()
    }

    #[test]
    fn attributes_and_labels() {
        let recovery = SecretKey::RecoveryKey;
        assert_eq!(
            key(&recovery),
            [
                ("application", "fogu".to_owned()),
                ("kind", "recovery-key".to_owned()),
            ]
        );
        assert_eq!(recovery.label(), "Fogu SSH scrollback recovery key");
        let pw = SecretKey::SshPassword {
            user: "alice".into(),
            host: "Box.Example".into(),
            port: 2222,
        };
        assert_eq!(
            key(&pw),
            [
                ("application", "fogu".to_owned()),
                ("host", "box.example".to_owned()),
                ("kind", "ssh-password".to_owned()),
                ("port", "2222".to_owned()),
                ("user", "alice".to_owned()),
            ]
        );
        assert_eq!(pw.label(), "Fogu SSH password for alice@Box.Example:2222");
        let default_port = SecretKey::SshPassword {
            user: "bob".into(),
            host: "h".into(),
            port: 22,
        };
        assert_eq!(default_port.label(), "Fogu SSH password for bob@h");
        let pass = SecretKey::KeyPassphrase {
            key_fingerprint: "0123456789abcdef".into(),
        };
        assert_eq!(
            key(&pass),
            [
                ("application", "fogu".to_owned()),
                ("key_fingerprint", "0123456789abcdef".to_owned()),
                ("kind", "key-passphrase".to_owned()),
            ]
        );
        assert_eq!(pass.label(), "Fogu SSH key passphrase (0123456789ab)");
        let script = SecretKey::LoginScript {
            profile_id: ProfileId("web".into()),
            name: "sudo".into(),
        };
        assert_eq!(key(&script).len(), 4);
        assert_eq!(script.label(), "Fogu login script answer (web: sudo)");
    }

    #[test]
    fn different_users_ports_and_hosts_never_share_a_key() {
        let a = |user: &str, host: &str, port| SecretKey::SshPassword {
            user: user.into(),
            host: host.into(),
            port,
        };
        assert_ne!(a("u", "h", 22).attributes(), a("v", "h", 22).attributes());
        assert_ne!(a("u", "h", 22).attributes(), a("u", "g", 22).attributes());
        assert_ne!(a("u", "h", 22).attributes(), a("u", "h", 23).attributes());
        assert_eq!(a("u", "H", 22).attributes(), a("u", "h", 22).attributes());
    }
}
