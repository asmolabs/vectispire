//! The agent's cryptography — a port of `ResultAttestation`, `SealingKeyAttestation` and
//! `SealedEnvelope` from `vectispire-common`'s `domain.crypto`.
//!
//! **Byte compatibility is the whole requirement.** The control plane verifies what this signs and
//! seals what this opens, with BouncyCastle: a message assembled with one separator less, a public
//! key in another encoding, and every result is refused or every deployment key unreadable. The
//! reference set `reference/crypto/` proves it both ways (see `tests/reference_set.rs`).
//!
//! What the agent does with each piece:
//! - [`ResultSigner`] signs a result, a failure report and the sealing-key announcement with the
//!   Ed25519 seed an administrator pinned for this agent (`VECTISPIRE_AGENT_SIGNING_KEY`);
//! - [`SealingKeyPair`] is the X25519 pair generated per process, whose public half is announced and
//!   to which the control plane seals deployment keys and HTTPS tokens.
//!
//! What the control plane does with it — the other half, added for the Rust control plane (task 2.3) and
//! used by no agent code: [`seal`] writes the envelope [`SealingKeyPair::open`] reads, byte for byte as
//! `SealedEnvelope.seal` writes it.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The separator between hashed fields — `Digests.SEPARATOR`, a NUL.
const SEPARATOR: [u8; 1] = [0];

const RESULT_CONTEXT: &[u8] = b"vectispire:agent-result:v1";
const FAILURE_CONTEXT: &[u8] = b"vectispire:agent-failure:v1";
const SEALING_KEY_CONTEXT: &[u8] = b"vectispire:agent-sealing-key:v2";

/// The header a result and a failure report carry their signature in.
pub const SIGNATURE_HEADER: &str = "X-Vectispire-Agent-Signature";

/// `java.util.Base64`'s basic encoder and its decoder, which accepts padding without requiring it.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// What a key or an envelope could not be used for.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The configured signing key is not 32 bytes of base64 — the Java side's sentence.
    #[error("The configured result-signing key is not 32 bytes of base64.")]
    SigningKey,
    /// The sealing-key announcement cannot be signed for these values.
    #[error("Only a usable X25519 key, a known agent and a positive generation can be signed.")]
    Unsignable,
    /// An envelope cannot be sealed to this key — `SealedEnvelope.seal`'s sentence.
    #[error("The recipient's sealing key is not a usable X25519 public key.")]
    Recipient,
}

fn decode(value: &str, expected_length: usize) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let raw = BASE64.decode(trimmed).ok()?;
    (raw.len() == expected_length).then_some(raw)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn result_message(context: &[u8], scan_id: i64, body: &[u8]) -> [u8; 32] {
    sha256(&[context, &SEPARATOR, scan_id.to_string().as_bytes(), &SEPARATOR, &sha256(&[body])])
}

/// The Ed25519 key an administrator pinned for this agent.
pub struct ResultSigner {
    key: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for ResultSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The seed is the agent's identity towards the control plane: never in a log line.
        formatter.debug_struct("ResultSigner").field("public", &self.public_key()).finish()
    }
}

impl ResultSigner {
    /// From the base64 seed `VECTISPIRE_AGENT_SIGNING_KEY` holds.
    pub fn from_base64_seed(seed: &str) -> Result<ResultSigner, CryptoError> {
        let raw = decode(seed, ed25519_dalek::SECRET_KEY_LENGTH).ok_or(CryptoError::SigningKey)?;
        let mut bytes = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        bytes.copy_from_slice(&raw);
        Ok(ResultSigner { key: ed25519_dalek::SigningKey::from_bytes(&bytes) })
    }

    /// The public half, base64 of its 32 raw bytes, as the control plane pins it.
    pub fn public_key(&self) -> String {
        BASE64.encode(self.key.verifying_key().as_bytes())
    }

    /// The signature over a result body, **over the exact bytes sent**.
    pub fn sign_result(&self, scan_id: i64, body: &[u8]) -> String {
        BASE64.encode(self.key.sign(&result_message(RESULT_CONTEXT, scan_id, body)).to_bytes())
    }

    /// The signature over a failure report — a context of its own, so neither stands for the other.
    pub fn sign_failure(&self, scan_id: i64, body: &[u8]) -> String {
        BASE64.encode(self.key.sign(&result_message(FAILURE_CONTEXT, scan_id, body)).to_bytes())
    }

    /// The signature over the sealing-key announcement: this agent, this generation, this key.
    pub fn sign_sealing_key(
        &self,
        agent_id: Uuid,
        generation: i64,
        sealing_public: &str,
    ) -> Result<String, CryptoError> {
        let message = sealing_key_message(SEALING_KEY_CONTEXT, agent_id, generation, sealing_public)
            .ok_or(CryptoError::Unsignable)?;
        Ok(BASE64.encode(self.key.sign(&message).to_bytes()))
    }
}

fn sealing_key_message(context: &[u8], agent_id: Uuid, generation: i64, sealing_public: &str) -> Option<[u8; 32]> {
    // A nil UUID is a UUID: the Java side refuses only an absent one, which a `Uuid` cannot be.
    if generation <= 0 || !is_usable_sealing_key(sealing_public) {
        return None;
    }
    let encoded = decode(sealing_public, SPKI_LENGTH)?;
    // The canonical, lower-case spelling, as `UUID.toString` writes it.
    let id = agent_id.hyphenated().to_string();
    Some(sha256(&[
        context,
        &SEPARATOR,
        id.as_bytes(),
        &SEPARATOR,
        generation.to_string().as_bytes(),
        &SEPARATOR,
        &sha256(&[&encoded]),
    ]))
}

/// Whether `signature` is `public_key`'s over a result — what the control plane checks.
pub fn verify_result(public_key: &str, scan_id: i64, body: &[u8], signature: &str) -> bool {
    verify(public_key, &result_message(RESULT_CONTEXT, scan_id, body), signature)
}

/// Whether `signature` is `public_key`'s over a failure report.
pub fn verify_failure(public_key: &str, scan_id: i64, body: &[u8], signature: &str) -> bool {
    verify(public_key, &result_message(FAILURE_CONTEXT, scan_id, body), signature)
}

/// Whether `signature` is `public_key`'s over a sealing-key announcement.
pub fn verify_sealing_key(
    public_key: &str,
    agent_id: Uuid,
    generation: i64,
    sealing_public: &str,
    signature: &str,
) -> bool {
    sealing_key_message(SEALING_KEY_CONTEXT, agent_id, generation, sealing_public)
        .is_some_and(|message| verify(public_key, &message, signature))
}

fn verify(public_key: &str, message: &[u8], signature: &str) -> bool {
    let (Some(key), Some(signature)) =
        (decode(public_key, ed25519_dalek::PUBLIC_KEY_LENGTH), decode(signature, ed25519_dalek::SIGNATURE_LENGTH))
    else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::try_from(key.as_slice()) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

/// Generates a fresh Ed25519 signing key pair, returning (public_key_base64, private_seed_base64).
pub fn generate_signing_key_pair() -> (String, String) {
    let mut seed = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
    let signer = ResultSigner { key: ed25519_dalek::SigningKey::from_bytes(&seed) };
    (signer.public_key(), BASE64.encode(seed))
}

/// Whether `value` is a valid Ed25519 public key in base64.
pub fn is_valid_signing_public_key(value: &str) -> bool {
    let Some(raw) = decode(value, ed25519_dalek::PUBLIC_KEY_LENGTH) else {
        return false;
    };
    ed25519_dalek::VerifyingKey::try_from(raw.as_slice()).is_ok()
}

// ---------------------------------------------------------------------------------- sealed secrets

/// The prefix of an envelope of the current format.
pub const SEALED_PREFIX: &str = "sealed:v2:";

const HKDF_INFO: &[u8] = b"vectispire:sealed-envelope:v2";
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

/// The DER `SubjectPublicKeyInfo` header of an X25519 key (RFC 8410): what BouncyCastle writes
/// before the 32 bytes, and what the salt and the associated data are computed over.
const X25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];
const SPKI_LENGTH: usize = X25519_SPKI_PREFIX.len() + 32;

/// Whether `value` is an X25519 public key in the encoding the control plane reads.
pub fn is_usable_sealing_key(value: &str) -> bool {
    decode(value, SPKI_LENGTH).is_some_and(|raw| raw[..X25519_SPKI_PREFIX.len()] == X25519_SPKI_PREFIX)
}

/// What a sealed secret is for — `SealedEnvelope.Context`. Bound into the associated data, so an
/// envelope sealed as a deployment key does not open as a token, nor a token as another host's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealContext(String);

impl SealContext {
    /// A repository's SSH deployment key.
    pub fn deployment_key() -> SealContext {
        SealContext("deployment-key".to_owned())
    }

    /// An HTTPS token, bound to the host and user name it is sent as.
    pub fn https_token(host: Option<&str>, username: Option<&str>) -> SealContext {
        let prefixed = |part: Option<&str>| match part {
            None => "-;".to_owned(),
            // `String.length()` counts UTF-16 units: so does this, for a host or user beyond ASCII.
            Some(part) => format!("{}:{part};", part.encode_utf16().count()),
        };
        SealContext(format!("https-token:{}{}", prefixed(host), prefixed(username)))
    }

    /// The value bound into the envelope.
    pub fn value(&self) -> &str {
        &self.0
    }
}

/// The X25519 pair this agent process seals to — generated at start, announced signed, never stored.
pub struct SealingKeyPair {
    secret: x25519_dalek::StaticSecret,
    public_spki: Vec<u8>,
}

impl std::fmt::Debug for SealingKeyPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SealingKeyPair").field("public", &self.public_key()).finish()
    }
}

impl SealingKeyPair {
    /// A fresh pair from the operating system's randomness.
    pub fn generate() -> SealingKeyPair {
        SealingKeyPair::from_secret(x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng))
    }

    /// The pair of a known secret — for the reference set, where the secret is a label's digest.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> SealingKeyPair {
        SealingKeyPair::from_secret(x25519_dalek::StaticSecret::from(bytes))
    }

    fn from_secret(secret: x25519_dalek::StaticSecret) -> SealingKeyPair {
        let public = x25519_dalek::PublicKey::from(&secret);
        let mut public_spki = X25519_SPKI_PREFIX.to_vec();
        public_spki.extend_from_slice(public.as_bytes());
        SealingKeyPair { secret, public_spki }
    }

    /// The public half, base64 of its `SubjectPublicKeyInfo`, as announced.
    pub fn public_key(&self) -> String {
        BASE64.encode(&self.public_spki)
    }

    /// The secret an envelope holds, or `None` for anything that does not open: another recipient,
    /// another context, a tampered byte, another format. Never an error that says which.
    pub fn open(&self, envelope: &str, context: &SealContext) -> Option<String> {
        let payload = BASE64.decode(envelope.strip_prefix(SEALED_PREFIX)?).ok()?;
        if payload.len() < SPKI_LENGTH + NONCE_LENGTH + TAG_LENGTH {
            return None;
        }
        let (ephemeral_spki, rest) = payload.split_at(SPKI_LENGTH);
        let (nonce, body) = rest.split_at(NONCE_LENGTH);
        if ephemeral_spki[..X25519_SPKI_PREFIX.len()] != X25519_SPKI_PREFIX {
            return None;
        }
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&ephemeral_spki[X25519_SPKI_PREFIX.len()..]);
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral));
        let session_key = session_key(shared.as_bytes(), ephemeral_spki, &self.public_spki)?;
        let cipher = Aes256Gcm::new_from_slice(&session_key).ok()?;
        let mut associated = ephemeral_spki.to_vec();
        associated.extend_from_slice(context.value().as_bytes());
        let plain = cipher.decrypt(Nonce::from_slice(nonce), Payload { msg: body, aad: &associated }).ok()?;
        String::from_utf8(plain).ok()
    }
}

/// `java.util.Base64`'s basic decoder for the sealing side, which reads the recipient's key exactly as
/// `SealedEnvelope.seal` does: padding optional, the two unused bits of a final quantum ignored, and nothing
/// trimmed — a key with white space around it is refused there, so it is refused here.
const JAVA_DECODER: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Seals `plain` to the agent whose announced key is `recipient_public`, for `context` —
/// `SealedEnvelope.seal`: `sealed:v2:` and the base64 of the ephemeral key's `SubjectPublicKeyInfo`, the
/// nonce and the AES-256-GCM output, the session key HKDF-SHA256 of the X25519 agreement, salted with the
/// digest of both keys, the associated data the ephemeral key and the context.
///
/// **One ephemeral pair per envelope**, from the operating system's randomness: two envelopes for the same
/// agent share no key material, so recovering one session key opens one envelope.
pub fn seal(recipient_public: &str, plain: &str, context: &SealContext) -> Result<String, CryptoError> {
    seal_with(&mut rand_core::OsRng, recipient_public, plain, context)
}

/// [`seal`] drawing from `random` exactly as Java draws from its `SecureRandom`: the ephemeral secret's 32
/// bytes first, then the 12 of the nonce. Given the stream Java was given, the envelope is the same bytes —
/// which is how the reference set holds the two to one format.
pub fn seal_with(
    random: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    recipient_public: &str,
    plain: &str,
    context: &SealContext,
) -> Result<String, CryptoError> {
    let recipient_spki = JAVA_DECODER.decode(recipient_public).map_err(|_| CryptoError::Recipient)?;
    let recipient = recipient_spki
        .strip_prefix(X25519_SPKI_PREFIX.as_slice())
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .ok_or(CryptoError::Recipient)?;

    let mut ephemeral_secret = [0u8; 32];
    random.fill_bytes(&mut ephemeral_secret);
    // Clamped by the multiplication, as BouncyCastle clamps the bytes it drew: the same scalar either way.
    let ephemeral = SealingKeyPair::from_secret_bytes(ephemeral_secret);
    let shared = ephemeral.secret.diffie_hellman(&x25519_dalek::PublicKey::from(recipient));
    let session_key =
        session_key(shared.as_bytes(), &ephemeral.public_spki, &recipient_spki).ok_or(CryptoError::Recipient)?;

    let mut nonce = [0u8; NONCE_LENGTH];
    random.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&session_key).map_err(|_| CryptoError::Recipient)?;
    let mut associated = ephemeral.public_spki.clone();
    associated.extend_from_slice(context.value().as_bytes());
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain.as_bytes(), aad: &associated })
        .map_err(|_| CryptoError::Recipient)?;

    let mut payload = ephemeral.public_spki.clone();
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&sealed);
    Ok(format!("{SEALED_PREFIX}{}", BASE64.encode(payload)))
}

fn session_key(shared: &[u8], ephemeral_spki: &[u8], recipient_spki: &[u8]) -> Option<[u8; 32]> {
    let salt = sha256(&[ephemeral_spki, recipient_spki]);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared).expand(HKDF_INFO, &mut key).ok()?;
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_that_is_not_32_bytes_is_refused_with_the_java_sentence() {
        let refused = ResultSigner::from_base64_seed("c2hvcnQ=").map(|_| ()).unwrap_err();
        assert_eq!(refused.to_string(), "The configured result-signing key is not 32 bytes of base64.");
    }

    #[test]
    fn a_result_signature_is_not_a_failure_signature() {
        let signer = ResultSigner::from_base64_seed(&BASE64.encode([7u8; 32])).unwrap();
        let signature = signer.sign_result(1, b"{}");
        assert!(verify_result(&signer.public_key(), 1, b"{}", &signature));
        assert!(!verify_failure(&signer.public_key(), 1, b"{}", &signature));
        assert!(!verify_result(&signer.public_key(), 2, b"{}", &signature));
    }

    #[test]
    fn the_context_is_length_prefixed_in_utf16_units() {
        assert_eq!(
            SealContext::https_token(Some("gitlab.example.org"), None).value(),
            "https-token:18:gitlab.example.org;-;"
        );
    }
}
