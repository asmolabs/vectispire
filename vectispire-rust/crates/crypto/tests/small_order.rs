//! **Keys of small order are refused where BouncyCastle refuses them** (Phase 2 security review, 2026-11).
//!
//! - An Ed25519 public key of small order verifies the signature `R` = identity, `s` = 0 over every message:
//!   pinned for an agent, it let anyone holding the agent's API key forge its results, failure reports and sealing-key
//!   announcement. Java's `Ed25519PublicKeyParameters` refuses such a point and its attestation answers `false`.
//! - An X25519 recipient of small order makes the agreement all zeros, so the envelope's session key follows from its
//!   own public bytes. Java's `X25519Agreement` throws "X25519 agreement failed" and nothing is sealed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use vectispire_crypto::{
    CryptoError, SEALED_PREFIX, SealContext, SealingKeyPair, seal, verify_failure, verify_result, verify_sealing_key,
};

/// Two of Ed25519's eight points of small order: the identity (y = 1) and the point of order 2 (y = −1).
fn weak_ed25519_keys() -> Vec<[u8; 32]> {
    let identity = {
        let mut point = [0u8; 32];
        point[0] = 1;
        point
    };
    let order_two = {
        let mut point = [0xffu8; 32];
        point[0] = 0xec;
        point[31] = 0x7f;
        point
    };
    vec![identity, order_two]
}

/// `R` = identity, `s` = 0: what verifies under a key of small order without any secret.
fn forged_signature() -> String {
    let mut signature = [0u8; 64];
    signature[0] = 1;
    BASE64.encode(signature)
}

#[test]
fn a_signing_key_of_small_order_verifies_nothing() {
    let agent = uuid::Uuid::from_u128(7);
    for key in weak_ed25519_keys() {
        let pinned = BASE64.encode(key);
        assert!(!verify_result(&pinned, 42, b"{}", &forged_signature()), "a result under {pinned}");
        assert!(!verify_failure(&pinned, 42, b"{}", &forged_signature()), "a failure report under {pinned}");
        let sealing = SealingKeyPair::generate().public_key();
        assert!(
            !verify_sealing_key(&pinned, agent, 1, &sealing, &forged_signature()),
            "a sealing-key announcement under {pinned}"
        );
    }
}

/// The X25519 SPKI header followed by the point `u`.
fn x25519_spki(u: [u8; 32]) -> Vec<u8> {
    let mut spki = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];
    spki.extend_from_slice(&u);
    spki
}

#[test]
fn nothing_is_sealed_to_a_recipient_of_small_order() {
    // u = 0 and u = 1, both of small order on Curve25519.
    for u in [[0u8; 32], {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    }] {
        let recipient = BASE64.encode(x25519_spki(u));
        assert_eq!(
            seal(&recipient, "a deployment key", &SealContext::deployment_key()).err(),
            Some(CryptoError::Recipient),
            "sealed to {recipient}"
        );
    }
}

/// An envelope whose ephemeral key is of small order, sealed the way an attacker who knows the agreement is zeros
/// would seal it: a valid tag under the session key anyone can compute. It must not open — the agent would otherwise
/// take a deployment key chosen by whoever wrote the claim's answer.
#[test]
fn an_envelope_from_an_ephemeral_key_of_small_order_does_not_open() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};

    let pair = SealingKeyPair::generate();
    let recipient_spki = BASE64.decode(pair.public_key()).unwrap();
    let ephemeral_spki = x25519_spki([0u8; 32]);
    let salt: [u8; 32] = Sha256::new().chain_update(&ephemeral_spki).chain_update(&recipient_spki).finalize().into();
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), &[0u8; 32]).expand(b"vectispire:sealed-envelope:v2", &mut key).unwrap();
    let context = SealContext::deployment_key();
    let mut associated = ephemeral_spki.clone();
    associated.extend_from_slice(context.value().as_bytes());
    let nonce = [0u8; 12];
    let body = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: b"a key the attacker chose", aad: &associated })
        .unwrap();
    let mut payload = ephemeral_spki;
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&body);
    let envelope = format!("{SEALED_PREFIX}{}", BASE64.encode(payload));
    assert_eq!(pair.open(&envelope, &context), None);
}
