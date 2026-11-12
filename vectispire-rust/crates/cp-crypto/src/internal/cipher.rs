//! AES-256-GCM at rest — `SecretCipher`, `EncryptionKey` and `LocalKmsProvider` of `common.domain.crypto`.
//!
//! **The format is Java's, byte for byte**: `v2:` and the standard base64 of the 12-byte nonce, the ciphertext
//! and the 16-byte tag, the context's UTF-8 as the associated data. The reference set `encryption/` holds the
//! two implementations to it in both directions.

use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use rand_core::RngCore;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use vectispire_domain::java;
use vectispire_domain::secret::Secret;
use zeroize::Zeroizing;

use crate::{Decrypted, SecretState};

/// The marker of every ciphertext this writes — `SecretCipher.FORMAT_PREFIX`.
pub const FORMAT_PREFIX: &str = "v2:";
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;

/// scrypt's cost — `N = 2^15`, `r = 8`, `p = 1`, once at start — and its fixed, application-specific salt.
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_SALT: &[u8] = b"vectispire.encryption.v2";

/// `java.util.Base64`'s decoders as Java reads a stored value or a key: the padding optional, **the unused bits
/// of a final quantum ignored** (Java does not look at them, and a value it reads must read here), nothing
/// trimmed, no line break. The encoder is the standard one with padding, which both decoders read back.
const fn java_decoder(alphabet: &'static base64::alphabet::Alphabet) -> GeneralPurpose {
    GeneralPurpose::new(
        alphabet,
        GeneralPurposeConfig::new()
            .with_encode_padding(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    )
}

pub const BASIC: GeneralPurpose = java_decoder(&base64::alphabet::STANDARD);
const URL: GeneralPurpose = java_decoder(&base64::alphabet::URL_SAFE);

/// The key that protects what is stored. Never printed, compared in constant time, wiped when dropped.
pub struct EncryptionKey(Zeroizing<[u8; KEY_LENGTH]>);

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the material: a key that prints itself ends up in a log, an error and a bug report.
        formatter.write_str("EncryptionKey[32 bytes]")
    }
}

impl PartialEq for EncryptionKey {
    /// Used for one thing, as in Java: dropping a key configured twice, so a rotated deployment does not try the
    /// same key as current and again as previous.
    fn eq(&self, other: &EncryptionKey) -> bool {
        bool::from(self.0.ct_eq(&*other.0))
    }
}

impl EncryptionKey {
    /// `EncryptionKey.derive`: 32 bytes of base64 used as they are, anything else a passphrase stretched with
    /// scrypt after NFKC. **Expensive by construction** for a passphrase: called once per configured secret, at
    /// start.
    pub fn derive(secret: &str) -> EncryptionKey {
        if let Some(raw) = decode_exact_key(secret) {
            return EncryptionKey(raw);
        }
        // NFKC first: two byte sequences that display identically must derive the same key, or a passphrase
        // typed on another keyboard stops opening the same secrets. **Not trimmed**: Java stretches the spaces
        // around a passphrase too, and a key that dropped them would read nothing Java wrote.
        let password = Zeroizing::new(secret.nfkc().collect::<String>());
        let mut material = Zeroizing::new([0u8; KEY_LENGTH]);
        // The parameters are constants scrypt accepts, and the output length is one it can fill: neither call can
        // fail, and an unreadable key would be worse than a panic at start.
        #[allow(clippy::expect_used)]
        let params =
            scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, KEY_LENGTH).expect("scrypt's fixed parameters");
        #[allow(clippy::expect_used)]
        scrypt::scrypt(password.as_bytes(), SCRYPT_SALT, &params, &mut *material).expect("a 32-byte scrypt output");
        EncryptionKey(material)
    }
}

/// The 32 bytes of a key written as base64, or `None` for a passphrase — `decodeExactKey`.
///
/// The shape is checked first (`^[A-Za-z0-9+/_-]{43,44}={0,2}$` on the `String.trim`med text), then the length
/// after decoding: a 44-character string that is not base64 of 32 bytes must not be taken for a key. A `-` or a
/// `_` anywhere selects the URL-safe decoder, which then refuses a `+` or a `/`: two alphabets mixed are a
/// passphrase, as they are in Java.
fn decode_exact_key(secret: &str) -> Option<Zeroizing<[u8; KEY_LENGTH]>> {
    let trimmed = java::trim(secret);
    let body = trimmed.trim_end_matches('=');
    let padding = trimmed.bytes().rev().take_while(|b| *b == b'=').count();
    let shaped = padding <= 2
        && (43..=44).contains(&body.len())
        && body.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-'));
    if !shaped {
        return None;
    }
    let decoder = if trimmed.contains(['-', '_']) { URL } else { BASIC };
    let decoded = Zeroizing::new(decoder.decode(trimmed).ok()?);
    let raw: [u8; KEY_LENGTH] = decoded.as_slice().try_into().ok()?;
    Some(Zeroizing::new(raw))
}

/// AES-256-GCM with the context as associated data — `SecretCipher`.
pub struct SecretCipher {
    random: Mutex<Box<dyn RngCore + Send>>,
}

impl std::fmt::Debug for SecretCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretCipher(AES-256-GCM)")
    }
}

impl SecretCipher {
    /// A cipher drawing its nonces from `random` — the operating system's in production; a labelled stream in
    /// the reference set, where the Java side's bytes are reproduced.
    pub fn new(random: Box<dyn RngCore + Send>) -> SecretCipher {
        SecretCipher { random: Mutex::new(random) }
    }

    /// `v2:` and the base64 of the nonce, the ciphertext and the tag. An empty value is written as it is.
    pub fn encrypt(&self, key: &EncryptionKey, plain: &str, context: &str) -> String {
        if plain.is_empty() {
            return String::new();
        }
        let mut nonce = [0u8; NONCE_LENGTH];
        // A poisoned lock is a panic elsewhere while drawing bytes: the generator itself is still usable.
        self.random.lock().unwrap_or_else(std::sync::PoisonError::into_inner).fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new((&*key.0).into());
        // Encryption verifies no tag; it fails only for a message beyond GCM's 64 GiB, which no stored secret is.
        #[allow(clippy::expect_used)]
        let sealed = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain.as_bytes(), aad: context.as_bytes() })
            .expect("a secret within GCM's limit");
        format!("{FORMAT_PREFIX}{}", BASIC.encode([nonce.as_slice(), &sealed].concat()))
    }

    /// The value under `key` in `context`, or `None` — **never an error that says why**: a wrong key, another
    /// context and an altered byte look alike, and telling them apart tells an attacker which one they got
    /// right. The tag is checked by `aes-gcm` in constant time before any plaintext is released.
    pub fn decrypt(&self, key: &EncryptionKey, encrypted: &str, context: &str) -> Option<Secret> {
        let combined = BASIC.decode(encrypted.strip_prefix(FORMAT_PREFIX)?).ok()?;
        if combined.len() < NONCE_LENGTH + TAG_LENGTH {
            return None;
        }
        let (nonce, body) = combined.split_at(NONCE_LENGTH);
        let cipher = Aes256Gcm::new((&*key.0).into());
        let plain = Zeroizing::new(
            cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: body, aad: context.as_bytes() }).ok()?,
        );
        // `new String(bytes, UTF_8)`: bytes that are not UTF-8 become U+FFFD, as Java reads them.
        Some(Secret::new(String::from_utf8_lossy(&plain).into_owned()))
    }

    /// The keys in order, the first answering CURRENT — `decryptWithAny`. **No fallback without associated
    /// data**: it would exist only to accept a relocated ciphertext.
    pub fn decrypt_with_any(&self, keys: &[EncryptionKey], encrypted: &str, context: &str) -> Decrypted {
        for (index, key) in keys.iter().enumerate() {
            if let Some(plain) = self.decrypt(key, encrypted, context) {
                return Decrypted::new(plain, if index == 0 { SecretState::Current } else { SecretState::PreviousKey });
            }
        }
        Decrypted::unreadable()
    }
}

/// The local keys — `LocalKmsProvider`: the current one encrypts, every configured one decrypts, current first.
#[derive(Debug)]
pub struct LocalKms {
    current: bool,
    keys: Vec<EncryptionKey>,
    cipher: SecretCipher,
}

impl LocalKms {
    /// `keys` holds the current key first when there is one.
    pub fn new(current: bool, keys: Vec<EncryptionKey>, cipher: SecretCipher) -> LocalKms {
        LocalKms { current, keys, cipher }
    }

    pub fn is_configured(&self) -> bool {
        self.current
    }

    /// Under the current key; `None` without one — the caller has refused before.
    pub fn encrypt(&self, plain: &str, context: &str) -> Option<String> {
        if plain.is_empty() {
            return Some(String::new());
        }
        let key = self.keys.first().filter(|_| self.current)?;
        Some(self.cipher.encrypt(key, plain, context))
    }

    pub fn inspect(&self, encrypted: &str, context: &str) -> Decrypted {
        self.cipher.decrypt_with_any(&self.keys, encrypted, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standard(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    #[test]
    fn a_base64_key_is_used_as_it_is_and_a_passphrase_is_not() {
        assert_eq!(*EncryptionKey::derive(&standard(7)).0, [7u8; 32]);
        assert_ne!(*EncryptionKey::derive("a passphrase").0, [0u8; 32]);
        assert_ne!(EncryptionKey::derive("a passphrase"), EncryptionKey::derive("another passphrase"));
        assert_eq!(format!("{:?}", EncryptionKey::derive(&standard(7))), "EncryptionKey[32 bytes]");
    }

    #[test]
    fn the_shape_is_checked_before_decoding() {
        // Three `=` is not a key's shape, whatever the decoder would say.
        assert!(decode_exact_key(&format!("{}==", standard(1))).is_none());
        assert!(decode_exact_key(&format!("{}=", &standard(1)[..43])).is_some());
        // 42 characters decode to 31 bytes: too short a body for the shape.
        assert!(decode_exact_key(&standard(1)[..42]).is_none());
        // A character outside both alphabets.
        assert!(decode_exact_key(&format!("{}.", &standard(1)[..43])).is_none());
    }
}
