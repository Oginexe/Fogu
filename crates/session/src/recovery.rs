//! Encryption for SSH scrollback saved by tab recovery. The key is text only while it crosses
//! the system keyring API; decoded key bytes are zeroed on drop.

use std::fmt::Write as _;

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom as _, SystemRandom};
use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret as _, SecretString};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

/// A random SSH scrollback key, hex encoded for the system keyring.
pub fn new_recovery_key() -> Result<SecretString, RecoveryCryptoError> {
    let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| RecoveryCryptoError::Random)?;
    let mut encoded = String::with_capacity(KEY_BYTES * 2);
    for byte in bytes.iter() {
        let _infallible = write!(encoded, "{byte:02x}");
    }
    Ok(SecretString::from(encoded))
}

/// Seals `plain` with a fresh nonce and authenticates the pane's recovery `key`.
pub fn seal_recovery(
    secret: &SecretString,
    key: &str,
    plain: &[u8],
) -> Result<Vec<u8>, RecoveryCryptoError> {
    let cipher = cipher(secret)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| RecoveryCryptoError::Random)?;
    let mut sealed = Zeroizing::new(plain.to_vec());
    cipher
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(key.as_bytes()),
            &mut *sealed,
        )
        .map_err(|_| RecoveryCryptoError::Seal)?;
    let mut file = Vec::with_capacity(NONCE_BYTES + sealed.len());
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&sealed);
    Ok(file)
}

/// Opens a file sealed for the pane's recovery `key`.
pub fn open_recovery(
    secret: &SecretString,
    key: &str,
    file: &[u8],
) -> Result<Zeroizing<Vec<u8>>, RecoveryCryptoError> {
    let (nonce, sealed) = file
        .split_at_checked(NONCE_BYTES)
        .ok_or(RecoveryCryptoError::Open)?;
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| RecoveryCryptoError::Open)?;
    let cipher = cipher(secret)?;
    let mut plain = Zeroizing::new(sealed.to_vec());
    let len = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(key.as_bytes()),
            &mut plain,
        )
        .map_err(|_| RecoveryCryptoError::Open)?
        .len();
    plain.truncate(len);
    Ok(plain)
}

/// Checks a keyring value before it is retained for recovery writes.
pub fn validate_recovery_key(secret: &SecretString) -> Result<(), RecoveryCryptoError> {
    cipher(secret).map(drop)
}

fn cipher(secret: &SecretString) -> Result<LessSafeKey, RecoveryCryptoError> {
    let text = secret.expose_secret().as_bytes();
    if text.len() != KEY_BYTES * 2 {
        return Err(RecoveryCryptoError::Key);
    }
    let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
    // The length check above leaves no remainder.
    let (pairs, _) = text.as_chunks::<2>();
    for (out, pair) in bytes.iter_mut().zip(pairs) {
        *out = (hex(pair[0]).ok_or(RecoveryCryptoError::Key)? << 4)
            | hex(pair[1]).ok_or(RecoveryCryptoError::Key)?;
    }
    // shortcut: ring does not zeroize its internal key copy, replace it if ring adds that support.
    let key = UnboundKey::new(&aead::CHACHA20_POLY1305, bytes.as_ref())
        .map_err(|_| RecoveryCryptoError::Key)?;
    Ok(LessSafeKey::new(key))
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Why SSH recovery encryption could not complete. No key material is included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryCryptoError {
    /// The operating system random source failed.
    #[error("the random source failed")]
    Random,
    /// The keyring value is not a valid recovery key.
    #[error("the recovery key is invalid")]
    Key,
    /// Encryption failed.
    #[error("scrollback encryption failed")]
    Seal,
    /// Authentication or decryption failed.
    #[error("scrollback authentication failed")]
    Open,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let secret = new_recovery_key().unwrap();
        let sealed = seal_recovery(&secret, "tab-a", b"private history").unwrap();
        assert_eq!(
            open_recovery(&secret, "tab-a", &sealed).unwrap().as_slice(),
            b"private history"
        );
    }

    #[test]
    fn malformed_keys_are_refused_before_use() {
        assert_eq!(
            validate_recovery_key(&SecretString::from("not-a-key")),
            Err(RecoveryCryptoError::Key)
        );
    }

    #[test]
    fn a_flipped_byte_is_refused() {
        let secret = new_recovery_key().unwrap();
        let mut sealed = seal_recovery(&secret, "tab-a", b"private history").unwrap();
        *sealed.last_mut().unwrap() ^= 1;
        assert!(open_recovery(&secret, "tab-a", &sealed).is_err());
    }

    #[test]
    fn a_file_from_another_tab_is_refused() {
        let secret = new_recovery_key().unwrap();
        let sealed = seal_recovery(&secret, "tab-a", b"private history").unwrap();
        assert!(open_recovery(&secret, "tab-b", &sealed).is_err());
    }

    #[test]
    fn a_wrong_key_is_refused() {
        let secret = new_recovery_key().unwrap();
        let wrong = new_recovery_key().unwrap();
        let sealed = seal_recovery(&secret, "tab-a", b"private history").unwrap();
        assert!(open_recovery(&wrong, "tab-a", &sealed).is_err());
    }
}
