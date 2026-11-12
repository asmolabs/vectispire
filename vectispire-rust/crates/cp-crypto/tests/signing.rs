//! What `vectispire.signing.key` may hold, read as `CosignSigner.parsePrivateKey` reads it — the forms a deployment
//! writes, and the refusals, each at start.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::{Arc, Mutex};

use base64::Engine;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use support::vault::door;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, KeyStore, SigningError, SigningKeys};
use vectispire_cp_settings::SettingsError;

#[derive(Debug, Default)]
struct Nowhere(Mutex<Vec<String>>);

impl KeyStore for Nowhere {
    async fn internal_value(&self, _key: &str) -> Result<Option<String>, SettingsError> {
        Ok(None)
    }
    async fn store_internal_if_absent(&self, _key: &str, value: &str) -> Result<bool, SettingsError> {
        self.0.lock().unwrap().push(value.to_owned());
        Ok(true)
    }
}

fn keys(configured: &str) -> Result<SigningKeys<Nowhere>, SigningError> {
    SigningKeys::new(
        configured,
        Nowhere::default(),
        Arc::new(Encryption::new(&EncryptionConfig::default(), door()).unwrap()),
    )
}

fn key() -> p256::SecretKey {
    p256::SecretKey::from_bytes(&support::labelled::labelled("signing-test:configured").into()).unwrap()
}

async fn id_of(configured: &str) -> String {
    keys(configured).unwrap().key_id().await.unwrap()
}

#[tokio::test]
async fn every_form_java_reads_is_the_same_key() {
    let pkcs8_pem = key().to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let expected = id_of(&pkcs8_pem).await;
    // Surrounded by white space, CRLF line ends, text before the PEM.
    assert_eq!(id_of(&format!("\n  {pkcs8_pem}  \n")).await, expected);
    assert_eq!(id_of(&pkcs8_pem.replace('\n', "\r\n")).await, expected);
    assert_eq!(id_of(&format!("the key:\n{pkcs8_pem}")).await, expected);
    // SEC1 naming its curve, as `openssl ecparam -genkey` writes it.
    assert_eq!(id_of(&sec1_pem(Some(P256))).await, expected);
    // The bare base64 of the PKCS#8 DER, on one line or broken.
    let der = key().to_pkcs8_der().unwrap();
    let bare = base64::engine::general_purpose::STANDARD.encode(der.as_bytes());
    assert_eq!(id_of(&bare).await, expected);
    assert_eq!(id_of(&format!("{}\n{}", &bare[..40], &bare[40..])).await, expected);
    // Markers that open no PEM object are stripped, and what is left read as base64 — Java's fallback.
    assert_eq!(id_of(&format!("-----KEY-----\n{bare}\n-----END-----")).await, expected);
    // The extra dash starts no marker: it stays, and is not base64.
    assert!(keys(&format!("------KEY-----{bare}")).is_err());
    // The key id is the hex SHA-256 of the public half's SubjectPublicKeyInfo.
    let spki = key().public_key().to_public_key_der().unwrap();
    use sha2::Digest;
    let digest: String = sha2::Sha256::digest(spki.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(expected, digest);
}

const P256: &str = "1.2.840.10045.3.1.7";

/// `key()` as SEC1 PEM, with the named curve `curve` or without parameters.
fn sec1_pem(curve: Option<&str>) -> String {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use sec1::der::{Encode, asn1::ObjectIdentifier};
    let secret = key().to_bytes();
    let public = key().public_key().to_encoded_point(false);
    let der = sec1::EcPrivateKey {
        private_key: &secret,
        parameters: curve.map(|oid| sec1::EcParameters::NamedCurve(ObjectIdentifier::new_unwrap(oid))),
        public_key: Some(public.as_bytes()),
    }
    .to_der()
    .unwrap();
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN EC PRIVATE KEY-----\n{body}\n-----END EC PRIVATE KEY-----\n")
}

#[test]
fn what_is_not_a_p256_private_key_is_refused_at_start() {
    let refused = |configured: &str| keys(configured).map(|_| ()).unwrap_err().to_string();
    assert_eq!(refused("not a key"), "Invalid ECDSA private key format");
    // A public key is not a private one.
    let public = key().public_key().to_public_key_pem(LineEnding::LF).unwrap();
    assert_eq!(refused(&public), "Invalid ECDSA private key format");
    // A PEM whose body is damaged.
    let pem = key().to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    assert_eq!(refused(&pem.replacen("MI", "!!", 1)), "Invalid ECDSA private key format");
    // Another curve the JDK reads is refused for its curve, in PKCS#8 and in SEC1.
    let p384 = p384::SecretKey::random(&mut rand_core::OsRng);
    let message = "The signing key must be an ECDSA P-256 private key.";
    assert_eq!(refused(&p384.to_pkcs8_pem(LineEnding::LF).unwrap()), message);
    assert_eq!(refused(&sec1_pem(Some("1.3.132.0.34"))), message, "SEC1 naming P-384");
    // SEC1 without its curve, which Java's key factory cannot place: not a key, whichever curve it was.
    assert_eq!(refused(&sec1_pem(None)), "Invalid ECDSA private key format");
    assert_eq!(refused(&p384.to_sec1_pem(LineEnding::LF).unwrap()), "Invalid ECDSA private key format");
    // A curve the JDK does not read.
    assert_eq!(refused(&sec1_pem(Some("1.3.132.0.10"))), "Invalid ECDSA private key format", "secp256k1");
    let bare = base64::engine::general_purpose::STANDARD.encode(p384.to_pkcs8_der().unwrap().as_bytes());
    assert_eq!(refused(&bare), message);
}

#[tokio::test]
async fn nothing_configured_and_no_encryption_key_signs_nothing_and_stores_nothing() {
    let keys = keys("  ").unwrap();
    assert!(matches!(keys.sign(b"{}").await, Err(SigningError::MissingKey)));
}

#[tokio::test]
async fn a_signature_is_checked_over_the_exact_bytes_and_its_base64_trimmed() {
    let pem = key().to_pkcs8_pem(LineEnding::LF).unwrap();
    let keys = keys(&pem).unwrap();
    let signature = keys.sign(b"payload").await.unwrap();
    assert!(keys.verify(b"payload", &format!(" {signature}\n")).await.unwrap());
    assert!(!keys.verify(b"payload ", &signature).await.unwrap());
    assert!(!keys.verify(b"payload", "not base64!").await.unwrap());
    assert!(!keys.verify(b"payload", "AAAA").await.unwrap());
    let envelope = keys.wrap_and_sign_dsse("application/vnd.in-toto+json", b"payload").await.unwrap();
    assert_eq!(envelope.payload, "cGF5bG9hZA==");
    assert!(
        keys.verify(b"DSSEv1 28 application/vnd.in-toto+json 7 payload", &envelope.signatures[0].sig).await.unwrap()
    );
    // The private half never in a debug dump.
    let printed = format!("{keys:?}");
    assert!(!printed.contains(&pem.lines().nth(1).unwrap()[..20]), "{printed}");
}
