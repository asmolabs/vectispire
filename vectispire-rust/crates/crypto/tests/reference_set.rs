//! Both directions of the agent's cryptography against the Java side's own answers.
//!
//! `reference/crypto/java-vectors.json` is written by `CryptoReferenceSetTest` in
//! `vectispire-common`; `reference/crypto/rust-vectors.json` by [`what_this_agent_signs`] here, and
//! the Java test verifies it. Private keys are never in either file: each is the SHA-256 of a label.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sha2::{Digest, Sha256};
use uuid::Uuid;
use vectispire_crypto::{ResultSigner, SealContext, SealingKeyPair};

const RUST_SEALING_LABEL: &str = "vectispire-rust-reference:rust-sealing-key";
/// The same label the Java side derives the pinned signing seed from.
const SIGNING_SEED_LABEL: &str = "vectispire-rust-reference:result-signing-seed";

fn labelled(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn signer() -> ResultSigner {
    ResultSigner::from_base64_seed(&base64(&labelled(SIGNING_SEED_LABEL))).unwrap()
}

#[test]
fn signatures_are_the_java_sides_bytes() {
    let java = vectispire_testkit::read_json("crypto/java-vectors.json");
    assert_eq!(java["signing_seed_label"], SIGNING_SEED_LABEL);
    let signer = signer();
    let scan_id = java["scan_id"].as_i64().unwrap();
    assert_eq!(signer.public_key(), java["signing_public"]);
    assert_eq!(signer.sign_result(scan_id, java["result_body"].as_str().unwrap().as_bytes()), java["result_signature"]);
    assert_eq!(
        signer.sign_failure(scan_id, java["failure_body"].as_str().unwrap().as_bytes()),
        java["failure_signature"]
    );

    let java_sealing = SealingKeyPair::from_secret_bytes(labelled(java["java_sealing_label"].as_str().unwrap()));
    assert_eq!(java_sealing.public_key(), java["java_sealing_public"], "the X25519 key's SubjectPublicKeyInfo bytes");
    let agent: Uuid = java["agent_id"].as_str().unwrap().parse().unwrap();
    let generation = java["generation"].as_i64().unwrap();
    assert_eq!(
        signer.sign_sealing_key(agent, generation, &java_sealing.public_key()).unwrap(),
        java["java_sealing_attestation"]
    );
}

#[test]
fn envelopes_the_control_plane_sealed_open_here_and_only_in_their_context() {
    let java = vectispire_testkit::read_json("crypto/java-vectors.json");
    let rust = SealingKeyPair::from_secret_bytes(labelled(RUST_SEALING_LABEL));
    let contexts = [
        SealContext::deployment_key(),
        SealContext::https_token(Some("gitlab.example.org"), Some("x-access-token")),
        SealContext::https_token(Some("gitlab.example.org"), None),
    ];
    let envelopes = java["envelopes_to_rust"].as_array().unwrap();
    assert_eq!(envelopes.len(), contexts.len());
    for (envelope, context) in envelopes.iter().zip(&contexts) {
        assert_eq!(envelope["context"], context.value());
        let sealed = envelope["sealed"].as_str().unwrap();
        assert_eq!(rust.open(sealed, context).as_deref(), envelope["plain"].as_str());
        for other in contexts.iter().filter(|other| *other != context) {
            assert_eq!(rust.open(sealed, other), None, "{} must not open as {}", context.value(), other.value());
        }
        let other_recipient = SealingKeyPair::from_secret_bytes(labelled("someone else"));
        assert_eq!(other_recipient.open(sealed, context), None);
    }
}

/// What the Java side verifies: a result, a failure report and the sealing-key announcement, signed
/// here over bodies of this side's choosing.
#[test]
fn what_this_agent_signs() {
    let signer = signer();
    let sealing = SealingKeyPair::from_secret_bytes(labelled(RUST_SEALING_LABEL));
    let agent = Uuid::parse_str("9d0c4e2a-71b3-4f55-8a6e-2c3b1d4e5f60").unwrap();
    let scan_id = 7_000_000_001_i64;
    let result_body = r#"{"secrets":[{"rule":"aws-access-token","description":"AWS","file":"deploy/é.env","line":1,"fingerprint":null}]}"#;
    let failure_body =
        r#"{"kind":"PERMANENT","message":"Branch \"main\" does not exist on https://gitlab.example.org/x."}"#;
    let vectors = serde_json::json!({
        "agent_id": agent.to_string(),
        "failure_body": failure_body,
        "failure_signature": signer.sign_failure(scan_id, failure_body.as_bytes()),
        "generation": 12,
        "result_body": result_body,
        "result_signature": signer.sign_result(scan_id, result_body.as_bytes()),
        "scan_id": scan_id,
        "sealing_attestation": signer.sign_sealing_key(agent, 12, &sealing.public_key()).unwrap(),
        "sealing_label": RUST_SEALING_LABEL,
        "sealing_public": sealing.public_key(),
    });
    vectispire_testkit::expect("crypto/rust-vectors.json", &(serde_json::to_string_pretty(&vectors).unwrap() + "\n"));
}
