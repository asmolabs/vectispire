//! The sealing side, which the control plane uses and the agent does not: against the envelopes Java sealed
//! (`reference/crypto/java-vectors.json`), byte for byte when given Java's stream of randomness.
//!
//! What the Java side opens of what this side seals is checked there, from `reference/encryption/`
//! (`EncryptionReferenceSetTest`, written by `vectispire-cp-crypto`'s reference test).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sha2::{Digest, Sha256};
use vectispire_crypto::{CryptoError, SEALED_PREFIX, SealContext, SealingKeyPair, seal, seal_with};

const RUST_SEALING_LABEL: &str = "vectispire-rust-reference:rust-sealing-key";

fn labelled(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

/// `CryptoReferenceSetTest.LabelledRandom`: SHA-256(label ‖ ":" ‖ counter) blocks, the counter moving once
/// per block and a call starting a fresh block — exactly as Java's `nextBytes` fills.
struct LabelledRandom {
    label: String,
    counter: u64,
}

impl rand_core::RngCore for LabelledRandom {
    fn next_u32(&mut self) -> u32 {
        unreachable!("the sealing side draws bytes only")
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!("the sealing side draws bytes only")
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(32) {
            let block = labelled(&format!("{}:{}", self.label, self.counter));
            self.counter += 1;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}

impl rand_core::CryptoRng for LabelledRandom {}

fn contexts() -> [SealContext; 3] {
    [
        SealContext::deployment_key(),
        SealContext::https_token(Some("gitlab.example.org"), Some("x-access-token")),
        SealContext::https_token(Some("gitlab.example.org"), None),
    ]
}

#[test]
fn given_java_s_randomness_the_envelope_is_java_s_bytes() {
    let java = vectispire_testkit::read_json("crypto/java-vectors.json");
    let recipient = SealingKeyPair::from_secret_bytes(labelled(RUST_SEALING_LABEL));
    // One stream for the three envelopes, as `CryptoReferenceSetTest` gave its one `SealedEnvelope`.
    let mut random = LabelledRandom { label: "vectispire-rust-reference:envelope".to_owned(), counter: 0 };
    let envelopes = java["envelopes_to_rust"].as_array().unwrap();
    assert_eq!(envelopes.len(), 3);
    for (envelope, context) in envelopes.iter().zip(contexts()) {
        assert_eq!(envelope["context"], context.value());
        let plain = envelope["plain"].as_str().unwrap();
        let sealed = seal_with(&mut random, &recipient.public_key(), plain, &context).unwrap();
        assert_eq!(sealed, envelope["sealed"].as_str().unwrap(), "{}", context.value());
    }
}

#[test]
fn what_is_sealed_opens_for_its_recipient_in_its_context_only() {
    let recipient = SealingKeyPair::generate();
    let someone_else = SealingKeyPair::generate();
    for context in contexts() {
        let sealed = seal(&recipient.public_key(), "invented material é 🔑", &context).unwrap();
        assert!(sealed.starts_with(SEALED_PREFIX));
        assert_eq!(recipient.open(&sealed, &context).as_deref(), Some("invented material é 🔑"));
        assert_eq!(someone_else.open(&sealed, &context), None);
        for other in contexts().iter().filter(|other| **other != context) {
            assert_eq!(recipient.open(&sealed, other), None);
        }
    }
    // Two seals of one secret share nothing: a fresh ephemeral key and nonce each time.
    let context = SealContext::deployment_key();
    assert_ne!(
        seal(&recipient.public_key(), "x", &context).unwrap(),
        seal(&recipient.public_key(), "x", &context).unwrap()
    );
}

#[test]
fn a_key_that_is_not_an_x25519_spki_is_refused_with_java_s_sentence() {
    let usable = SealingKeyPair::generate().public_key();
    let context = SealContext::deployment_key();
    let refused = |key: &str| seal(key, "x", &context).unwrap_err();
    assert_eq!(refused(""), CryptoError::Recipient);
    assert_eq!(refused("not base64!"), CryptoError::Recipient);
    // Java's decoder trims nothing: a key with a space around it is refused there, so here.
    assert_eq!(refused(&format!(" {usable}")), CryptoError::Recipient);
    assert_eq!(refused(&format!("{usable}\n")), CryptoError::Recipient);
    // The 32 raw bytes without their SubjectPublicKeyInfo header, and an Ed25519 header instead of X25519's.
    let raw = labelled("raw");
    use base64::Engine;
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    assert_eq!(refused(&b64(&raw)), CryptoError::Recipient);
    let mut ed25519 = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    ed25519.extend_from_slice(&raw);
    assert_eq!(refused(&b64(&ed25519)), CryptoError::Recipient);
    // One byte too many.
    let mut longer = base64::engine::general_purpose::STANDARD.decode(&usable).unwrap();
    longer.push(0);
    assert_eq!(refused(&b64(&longer)), CryptoError::Recipient);
    assert_eq!(CryptoError::Recipient.to_string(), "The recipient's sealing key is not a usable X25519 public key.");
    // The two unused bits of the last character set: Java's decoder does not look at them, so neither does this.
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (data, padding) = usable.split_at(usable.trim_end_matches('=').len());
    let (head, last) = data.split_at(data.len() - 1);
    let index = alphabet.find(last).unwrap();
    let noisy = format!("{head}{}{padding}", &alphabet[(index | 1)..=(index | 1)]);
    assert_ne!(noisy, usable);
    assert!(seal(&noisy, "x", &context).is_ok());
    // Without its padding, Java reads it: so does this side.
    let unpadded = usable.trim_end_matches('=');
    assert!(seal(unpadded, "x", &context).is_ok());
}
