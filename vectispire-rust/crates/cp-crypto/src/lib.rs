//! The control plane's crypto module — `core.crypto` and the parts of `common.domain.crypto` it is built on
//! (plan, Phase 2 task 2.3).
//!
//! - [`Encryption`] — `EncryptionService`: AES-256-GCM at rest with the context as associated data, the key
//!   derived as Java derives it, rotation through previous keys, or HashiCorp Vault's Transit engine reached
//!   through the outbound door (`vectispire-cp-outbound`) and nothing else.
//! - [`SigningKeys`] — `SigningKeyService`: the P-256 key every document is signed with, configured or kept
//!   encrypted in an internal settings row.
//! - The contexts a ciphertext is bound to ([`private_key_context`] and its siblings), each built in one place.
//!
//! **Where the key comes from is not decided here.** `ENCRYPTION_KEY`, `ENCRYPTION_KEY_FILE`, the config tree under
//! `/run/secrets` and their refusals are `vectispire-cp-runtime`'s reading of the environment (`EncryptionProperties
//! .resolved()` and `SecretFile`, ported there with the rest of the configuration); the composition hands the
//! resolved values to [`EncryptionConfig`]. A module may not depend on the runtime, and the runtime already reads
//! every other secret file the same way.
//!
//! **Everything this writes is stored, and Java reads it back** after a switch in either direction. The reference
//! set `reference/encryption/` holds the two to the same bytes: see `tests/reference_set.rs`.

#![forbid(unsafe_code)]

mod encryption;
mod internal;
mod signing;

pub use encryption::{
    Decrypted, Encryption, EncryptionConfig, EncryptionError, MISSING_KEY, SecretState, StartupRefusal, VaultDoor,
};
pub use signing::{DsseEnvelope, DsseSignature, KeyStore, STORED_KEY, SigningError, SigningKeys, Verification};

/// Where a private SSH key lives — `SecretCipher.privateKeyContext`. Encrypting under one context and reading
/// under another makes the value unreadable, so the string is only ever built here.
pub fn private_key_context(key_id: &str) -> String {
    format!("ssh_key:{key_id}:private_key")
}

/// Where an HTTPS clone token lives — the same rule.
pub fn git_token_context(token_id: &str) -> String {
    format!("git_token:{token_id}:token")
}

/// Where a forge connection's token lives (decision 0037 §2) — the same rule.
pub fn forge_connection_context(connection_id: &str) -> String {
    format!("forge_connection:{connection_id}:token")
}

/// `SecretCipher.secretEquals`: for a comparison whose operand is itself a secret, in constant time.
pub fn secret_equals(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq;
    // BouncyCastle's `constantTimeAreEqual` answers false for two lengths at once, without looking further;
    // `subtle` does the same.
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}
