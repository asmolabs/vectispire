//! Both directions of encryption at rest, the Vault exchanges and the signing key, against the Java side.
//!
//! `reference/encryption/java-vectors.json` is written by `EncryptionReferenceSetTest` (vectispire-core): this
//! side reproduces its ciphertexts byte for byte from the same nonce stream and reads every value as Java read it.
//! `reference/encryption/rust-vectors.json` is written by [`what_this_side_writes`], and the same Java test reads
//! it back — the ciphertexts through `EncryptionService`, the envelopes through `SealedEnvelope`, the signing-key
//! row through `SigningKeyService`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::{Arc, Mutex};

use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};
use support::labelled::{LabelledRandom, labelled, standard_key};
use support::vault::{Stub, door};
use vectispire_cp_crypto::{
    Encryption, EncryptionConfig, EncryptionError, KeyStore, MISSING_KEY, SigningError, SigningKeys,
};
use vectispire_cp_settings::SettingsError;
use vectispire_crypto::{SealContext, SealingKeyPair, seal_with};
use vectispire_domain::secret::Secret;

const SIGNING_CONTEXT: &str = "internal:document_signing_key";
const JAVA_SEALING_LABEL: &str = "vectispire-rust-reference:java-sealing-key";
const RUST_SIGNING_LABEL: &str = "vectispire-rust-reference:rust-signing-key";

fn java() -> Value {
    vectispire_testkit::read_json("encryption/java-vectors.json")
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_else(|| panic!("not a string: {value}"))
}

fn config(current: Option<&str>, previous: &[&str]) -> EncryptionConfig {
    EncryptionConfig {
        key: current.map(Secret::new),
        previous_keys: previous.iter().map(|key| Secret::new(*key)).collect(),
        ..EncryptionConfig::default()
    }
}

fn writer(configured: &str, stream: &str) -> Encryption {
    Encryption::with_random(&config(Some(configured), &[]), door(), LabelledRandom::boxed(stream)).unwrap()
}

fn reader(current: Option<&str>, previous: &[&str]) -> Encryption {
    Encryption::new(&config(current, previous), door()).unwrap()
}

/// One row of `t_setting`, in memory.
#[derive(Debug, Default)]
struct Row(Mutex<Option<String>>);

impl KeyStore for Row {
    async fn internal_value(&self, _key: &str) -> Result<Option<String>, SettingsError> {
        Ok(self.0.lock().unwrap().clone())
    }

    async fn store_internal_if_absent(&self, _key: &str, value: &str) -> Result<bool, SettingsError> {
        let mut row = self.0.lock().unwrap();
        if row.is_some() {
            return Ok(false);
        }
        *row = Some(value.to_owned());
        Ok(true)
    }
}

impl Row {
    fn holding(value: &str) -> Row {
        Row(Mutex::new(Some(value.to_owned())))
    }
}

#[tokio::test]
async fn every_derivation_reads_and_writes_java_s_bytes() {
    let java = java();
    for case in java["derivations"].as_array().unwrap() {
        let name = text(&case["name"]);
        let configured = text(&case["configured"]);
        let (plain, context, cipher) = (text(&case["plain"]), text(&case["context"]), text(&case["cipher"]));
        let stream = format!("vectispire-rust-reference:derivation:{name}");
        let written = writer(configured, &stream).encrypt(plain, context).await.unwrap();
        assert_eq!(written, cipher, "{name}: the same key and nonce write the same bytes");
        let read = reader(Some(configured), &[]).inspect(cipher, context).await;
        assert_eq!((read.plain_text(), read.state().name()), (plain, "CURRENT"), "{name}");
        if let Some(label) = case["label"].as_str() {
            // The key derived from the spelling is the label's raw key exactly when Java said so.
            let as_raw = writer(&standard_key(label), &stream).encrypt(plain, context).await.unwrap();
            assert_eq!(as_raw == cipher, case["raw"].as_bool().unwrap(), "{name}: raw or stretched, as Java");
        }
    }
}

#[tokio::test]
async fn each_context_is_written_as_java_writes_it_and_read_only_there() {
    let java = java();
    let standard = standard_key(text(&java["key_label"]));
    let writer = writer(&standard, "vectispire-rust-reference:contexts");
    let read = reader(Some(&standard), &[]);
    let cases = java["contexts"].as_array().unwrap();
    for case in cases {
        let (context, plain, cipher) = (text(&case["context"]), text(&case["plain"]), text(&case["cipher"]));
        assert_eq!(writer.encrypt(plain, context).await.unwrap(), cipher, "{context}");
        assert_eq!(read.inspect(cipher, context).await.plain_text(), plain);
        for other in cases.iter().map(|other| text(&other["context"])).filter(|other| *other != context) {
            assert_eq!(read.inspect(cipher, other).await.state().name(), "UNREADABLE", "{context} read as {other}");
        }
    }
    assert_eq!(reader(None, &[]).encrypt("", "ssh_key:7:private_key").await.unwrap(), "");
}

#[tokio::test]
async fn rotation_reports_which_key_read_a_value_as_java_does() {
    for rotation in java()["rotations"].as_array().unwrap() {
        let previous: Vec<&str> = rotation["previous"].as_array().unwrap().iter().map(text).collect();
        let encryption = reader(rotation["current"].as_str(), &previous);
        assert_eq!(encryption.is_configured(), rotation["configured"].as_bool().unwrap());
        for value in rotation["values"].as_array().unwrap() {
            let read = encryption.inspect(text(&value["cipher"]), text(&value["context"])).await;
            assert_eq!(
                (read.state().name(), read.plain_text()),
                (text(&value["state"]), text(&value["plain"])),
                "{rotation}"
            );
        }
    }
}

#[tokio::test]
async fn what_reads_and_what_does_not_is_java_s_answer() {
    let java = java();
    let reader = reader(Some(&standard_key(text(&java["key_label"]))), &[]);
    for case in java["readings"].as_array().unwrap() {
        let stored = text(&case["stored"]);
        let read = reader.inspect(stored, text(&case["context"])).await;
        let name = text(&case["name"]);
        assert_eq!(read.state().name(), text(&case["state"]), "{name}");
        assert_eq!(read.plain_text(), text(&case["plain"]), "{name}");
        assert_eq!(Encryption::is_ciphertext(stored), case["is_ciphertext"].as_bool().unwrap(), "{name}");
    }
    for case in java["stored_secrets"].as_array().unwrap() {
        let read = reader.read_secret(text(&case["stored"]), text(&case["context"]), "The test credential").await;
        assert_eq!(read.expose(), text(&case["read"]), "{case}");
    }
}

#[tokio::test]
async fn the_sentences_an_operator_reads_are_java_s() {
    let java = java();
    let messages = &java["messages"];
    let refused = |class: &str, message: String| format!("{class}: {message}");
    assert_eq!(MISSING_KEY, text(&messages["missing_key"]));
    assert_eq!(EncryptionError::MissingKey.to_string(), MISSING_KEY);
    let key = standard_key(text(&java["key_label"]));
    assert_eq!(reader(None, &[]).encrypt("x", "c").await, Err(EncryptionError::MissingKey));

    let vault = |endpoint: Option<&str>, token: Option<&str>| EncryptionConfig {
        kms_type: Some(" Vault ".to_owned()),
        vault_endpoint: endpoint.map(str::to_owned),
        vault_token: token.map(Secret::new),
        ..config(Some(&key), &[])
    };
    let refusal = Encryption::new(&vault(None, Some("s.stub")), door()).unwrap_err();
    assert_eq!(refused("IllegalStateException", refusal.0), text(&messages["vault_without_endpoint"]));
    let refusal = Encryption::new(&vault(Some("https://vault.invalid"), None), door()).unwrap_err();
    assert_eq!(refused("IllegalStateException", refusal.0), text(&messages["vault_without_token"]));
    // A blank endpoint is no endpoint.
    assert!(Encryption::new(&vault(Some("  "), Some("s.stub")), door()).unwrap_err().0.contains("no endpoint"));

    let encryption = Arc::new(reader(Some(&key), &[]));
    let unreadable =
        SigningKeys::new("", Row::holding("v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), encryption.clone())
            .unwrap();
    let error = unreadable.sign(b"{}").await.unwrap_err();
    assert!(matches!(error, SigningError::Unreadable));
    assert_eq!(refused("IllegalStateException", error.to_string()), text(&messages["signing_key_unreadable"]));

    let p384 = p384::SecretKey::random(&mut rand_core::OsRng).to_pkcs8_pem(LineEnding::LF).unwrap();
    let error = SigningKeys::new(&p384, Row::default(), encryption.clone()).unwrap_err();
    assert_eq!(refused("IllegalArgumentException", error.to_string()), text(&messages["signing_key_not_p256"]));
    let error = SigningKeys::new("not a key", Row::default(), encryption.clone()).unwrap_err();
    assert_eq!(refused("IllegalArgumentException", error.to_string()), text(&messages["signing_key_unparsable"]));

    // SEC1, as BouncyCastle's `ECPrivateKey(256, s, parameters)` encodes the Java signing key's scalar.
    let scalar = labelled(text(&java["signing"]["label"]));
    let sec1 = |curve: Option<&str>| {
        use sec1::der::{Encode, asn1::ObjectIdentifier};
        let der = sec1::EcPrivateKey {
            private_key: &scalar,
            parameters: curve.map(|oid| sec1::EcParameters::NamedCurve(ObjectIdentifier::new_unwrap(oid))),
            public_key: None,
        }
        .to_der()
        .unwrap();
        use base64::Engine;
        let body = base64::engine::general_purpose::STANDARD.encode(der);
        format!("-----BEGIN EC PRIVATE KEY-----\n{body}\n-----END EC PRIVATE KEY-----\n")
    };
    let answer = |pem: String| {
        let encryption = encryption.clone();
        async move {
            match SigningKeys::new(&pem, Row::default(), encryption) {
                Ok(keys) => format!("key id {}", keys.key_id().await.unwrap()),
                Err(error) => refused("IllegalArgumentException", error.to_string()),
            }
        }
    };
    assert_eq!(answer(sec1(Some("1.2.840.10045.3.1.7"))).await, text(&messages["sec1_named_p256"]));
    assert_eq!(text(&messages["sec1_named_p256"]), format!("key id {}", text(&java["signing"]["fingerprint"])));
    assert_eq!(answer(sec1(Some("1.3.132.0.34"))).await, text(&messages["sec1_named_p384"]));
    assert_eq!(answer(sec1(None)).await, text(&messages["sec1_without_curve"]));
    // A deliberate difference (README): Java takes a secp256k1 key — the JDK reads the curve — and publishes as its
    // public half the P-256 point of its scalar, which verifies nothing it signs. Refused here, at start.
    assert!(text(&messages["sec1_named_secp256k1"]).starts_with("key id "));
    assert_eq!(answer(sec1(Some("1.3.132.0.10"))).await, "IllegalArgumentException: Invalid ECDSA private key format");
}

#[tokio::test]
async fn the_signing_key_java_stored_signs_and_verifies_here() {
    let java = java();
    let signing = &java["signing"];
    let encryption = Arc::new(reader(Some(&standard_key(text(&java["key_label"]))), &[]));
    let keys = SigningKeys::new("", Row::holding(text(&signing["row"])), encryption).unwrap();

    assert_eq!(vectispire_cp_crypto::STORED_KEY, text(&signing["setting"]), "the row Java reads");
    assert_eq!(keys.public_key_pem().await.unwrap(), text(&signing["public_pem"]));
    assert_eq!(keys.key_id().await.unwrap(), text(&signing["fingerprint"]));
    let payload = text(&signing["payload"]).as_bytes();
    assert!(keys.verify(payload, text(&signing["signature"])).await.unwrap());
    assert!(!keys.verify(b"{}", text(&signing["signature"])).await.unwrap());

    // DSSE: the same pre-authentication encoding, Java's signature over it verifies, and ours is over it too.
    let pae = text(&signing["pre_authentication_encoding"]).as_bytes();
    assert!(keys.verify(pae, text(&signing["dsse_signature"])).await.unwrap());
    let envelope = keys.wrap_and_sign_dsse(text(&signing["dsse_payload_type"]), payload).await.unwrap();
    assert_eq!(envelope.payload, text(&signing["dsse_payload"]));
    assert_eq!(envelope.signatures[0].keyid, text(&signing["fingerprint"]));
    assert!(keys.verify(pae, &envelope.signatures[0].sig).await.unwrap());

    let theirs = keys
        .verify_with(payload, text(&signing["other_signature"]), Some(text(&signing["other_public_pem"])))
        .await
        .unwrap();
    let expected = &signing["other_verification"];
    assert_eq!(
        (theirs.valid, theirs.key_id.as_str(), theirs.vectispire_key, theirs.message.as_str()),
        (
            expected["valid"].as_bool().unwrap(),
            text(&expected["fingerprint"]),
            expected["vectispire"].as_bool().unwrap(),
            text(&expected["message"])
        )
    );
    let messages = &signing["verification_messages"];
    let ours = keys.sign(payload).await.unwrap();
    let message = |verification: vectispire_cp_crypto::Verification| verification.message;
    assert_eq!(message(keys.verify_with(payload, &ours, None).await.unwrap()), text(&messages["ours_valid"]));
    assert_eq!(message(keys.verify_with(b"{}", &ours, Some("  ")).await.unwrap()), text(&messages["ours_invalid"]));
    assert_eq!(
        message(
            keys.verify_with(b"{}", text(&signing["other_signature"]), Some(text(&signing["other_public_pem"])))
                .await
                .unwrap()
        ),
        text(&messages["supplied_invalid"])
    );
    let pem = keys.public_key_pem().await.unwrap();
    assert_eq!(
        message(keys.verify_with(payload, &ours, Some(&pem)).await.unwrap()),
        text(&messages["supplied_ours_valid"])
    );
    assert!(matches!(keys.verify_with(payload, &ours, Some("not a key")).await, Err(SigningError::InvalidPublicKey)));
    // Configured rather than stored, the same key: the decrypted PEM, as `vectispire.signing.key` would carry it.
    let decrypted = reader(Some(&standard_key(text(&java["key_label"]))), &[])
        .inspect(text(&signing["row"]), SIGNING_CONTEXT)
        .await;
    let configured = SigningKeys::new(decrypted.plain_text(), Row::default(), Arc::new(reader(None, &[]))).unwrap();
    assert_eq!(configured.key_id().await.unwrap(), text(&signing["fingerprint"]));
}

#[tokio::test]
async fn the_transit_exchanges_are_java_s() {
    let java = java();
    let local = standard_key(text(&java["key_label"]));
    for scenario in java["vault"].as_array().unwrap() {
        let name = text(&scenario["name"]);
        let answer =
            |status: &str, body: &str| (scenario[status].as_u64().unwrap() as u16, text(&scenario[body]).to_owned());
        let (key_status, key_body) = answer("key_status", "key_body");
        let (status, body) = answer("status", "body");
        let stub = Stub::start(vec![
            ("/v1/transit/keys/", key_status, key_body),
            ("/v1/transit/encrypt/", status, body.clone()),
            ("/v1/transit/decrypt/", status, body),
        ])
        .await;
        let encryption = Encryption::new(
            &EncryptionConfig {
                kms_type: Some("vault".to_owned()),
                vault_endpoint: Some(format!("{}//", stub.endpoint())),
                vault_token: Some(Secret::new("s.stub")),
                vault_key_name: Some(" ".to_owned()),
                ..config(Some(&local), &[])
            },
            door(),
        )
        .unwrap();
        assert!(encryption.is_externally_managed());

        let (input, context) = (text(&scenario["input"]), text(&scenario["context"]));
        let outcome = &scenario["outcome"];
        if text(&scenario["operation"]) == "encrypt" {
            match encryption.encrypt(input, context).await {
                Ok(cipher) => assert_eq!(cipher, text(&outcome["cipher"]), "{name}"),
                Err(refused) => {
                    let expected = text(&outcome["refused"]);
                    if name == "encrypt answered with what is not JSON" {
                        // The parser's own words follow, and Jackson's are not serde's.
                        let prefix = "Vault KMS encryption failed: ";
                        assert!(expected.starts_with(prefix) && refused.to_string().starts_with(prefix), "{refused}");
                    } else {
                        assert_eq!(refused.to_string(), expected, "{name}");
                    }
                }
            }
        } else {
            let read = encryption.inspect(input, context).await;
            assert_eq!(
                (read.state().name(), read.plain_text()),
                (text(&outcome["state"]), text(&outcome["plain"])),
                "{name}"
            );
        }

        let made = stub.requests();
        let expected = scenario["requests"].as_array().unwrap();
        assert_eq!(made.len(), expected.len(), "{name}: {made:?}");
        for (request, java) in made.iter().zip(expected) {
            assert_eq!(request.method, text(&java["method"]), "{name}");
            assert_eq!(request.path, text(&java["url"]).trim_start_matches("http://127.0.0.1:8200"), "{name}");
            for (header, value) in java["headers"].as_object().unwrap() {
                assert_eq!(request.header(&header.to_lowercase()), Some(text(value)), "{name}: {header}");
            }
            if java["body"].is_null() {
                assert_eq!(request.body, "", "{name}");
                assert_eq!(request.header("content-type"), None, "{name}");
            } else {
                assert_eq!(serde_json::from_str::<Value>(&request.body).unwrap(), java["body"], "{name}");
            }
        }
    }
}

/// What the Java side reads back (`EncryptionReferenceSetTest.whatTheRustPortWroteReadsHere`).
#[tokio::test]
async fn what_this_side_writes() {
    let java = java();
    let standard = standard_key(text(&java["key_label"]));
    let passphrase = "a passphrase written by the Rust side, invented";
    let mut ciphers = Vec::new();
    for configured in [standard.as_str(), passphrase] {
        let writer = writer(configured, "vectispire-rust-reference:rust-ciphers");
        for (context, plain) in [
            ("ssh_key:7:private_key", "invented deployment key material\nsecond line\n"),
            ("git_token:12:token", "invented clone token"),
            ("forge_connection:3:token", "invented forge token"),
            ("user:totp_secret:5", "INVENTEDTOTPSEEDAAAA"),
            ("é:ü:🔑", "unicode é ü 中文 🔑"),
            ("", "no associated data at all"),
        ] {
            let cipher = writer.encrypt(plain, context).await.unwrap();
            ciphers.push(json!({"configured": configured, "context": context, "plain": plain, "cipher": cipher}));
        }
    }

    let java_sealing = SealingKeyPair::from_secret_bytes(labelled(JAVA_SEALING_LABEL)).public_key();
    let mut random = LabelledRandom::new("vectispire-rust-reference:rust-envelopes");
    let mut envelopes = Vec::new();
    for context in [
        SealContext::deployment_key(),
        SealContext::https_token(Some("gitlab.example.org"), Some("x-access-token")),
        SealContext::https_token(None, Some("é")),
    ] {
        let plain = format!("invented material sealed by Rust for {}", context.value());
        let sealed = seal_with(&mut random, &java_sealing, &plain, &context).unwrap();
        envelopes.push(json!({"context": context.value(), "plain": plain, "sealed": sealed}));
    }

    let key = p256::ecdsa::SigningKey::from_bytes(&labelled(RUST_SIGNING_LABEL).into()).unwrap();
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let row = writer(&standard, "vectispire-rust-reference:rust-signing").encrypt(&pem, SIGNING_CONTEXT).await.unwrap();
    let keys = SigningKeys::new("", Row::holding(&row), Arc::new(reader(Some(&standard), &[]))).unwrap();
    let payload = "{\"status\":\"passed\",\"by\":\"rust\"}";
    let envelope = keys.wrap_and_sign_dsse("application/vnd.in-toto+json", payload.as_bytes()).await.unwrap();
    // The stored and the configured readings of one key agree.
    let configured = SigningKeys::new(&pem, Row::default(), Arc::new(reader(None, &[]))).unwrap();
    assert_eq!(configured.key_id().await.unwrap(), keys.key_id().await.unwrap());

    let vectors = json!({
        "ciphers": ciphers,
        "sealed_to": java_sealing,
        "envelopes": envelopes,
        "signing": {
            "label": RUST_SIGNING_LABEL,
            "configured": standard,
            "context": SIGNING_CONTEXT,
            "row": row,
            "public_pem": keys.public_key_pem().await.unwrap(),
            "fingerprint": keys.key_id().await.unwrap(),
            "payload": payload,
            "signature": keys.sign(payload.as_bytes()).await.unwrap(),
            "dsse_payload_type": envelope.payload_type,
            "dsse_payload": envelope.payload,
            "dsse_signature": envelope.signatures[0].sig,
        },
    });
    vectispire_testkit::expect(
        "encryption/rust-vectors.json",
        &(serde_json::to_string_pretty(&vectors).unwrap() + "\n"),
    );
}
