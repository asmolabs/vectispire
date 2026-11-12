//! `EncryptionServiceTest`, `EncryptionKeyFileTest`'s "the file form is the same key" with the chain
//! `EncryptionKeyFileDatabaseTest` covers, and `VaultKmsProviderTest`, ported.
//!
//! The key file's refusals themselves (missing, empty, both a value and a file) are `vectispire-cp-runtime`'s, which
//! reads the environment, and are tested there (`secret_file`, `settings`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use support::labelled::standard_key;
use support::vault::{Stub, door};
use vectispire_cp_crypto::{Encryption, EncryptionConfig, EncryptionError, SecretState, private_key_context};
use vectispire_cp_runtime::property::Environment;
use vectispire_domain::secret::Secret;

const CONTEXT: &str = "ssh_key:7";

fn current() -> String {
    standard_key("encryption-test:current")
}

fn previous() -> String {
    standard_key("encryption-test:previous")
}

fn service(key: Option<&str>, previous: &[&str]) -> Encryption {
    Encryption::new(
        &EncryptionConfig {
            key: key.map(Secret::new),
            previous_keys: previous.iter().map(|key| Secret::new(*key)).collect(),
            ..EncryptionConfig::default()
        },
        door(),
    )
    .unwrap()
}

#[tokio::test]
async fn round_trips_under_the_current_key() {
    let service = service(Some(&current()), &[]);
    let encrypted = service.encrypt("ssh-rsa-test-private-key-material", CONTEXT).await.unwrap();
    assert!(!encrypted.contains("test-private-key"));
    assert!(encrypted.starts_with("v2:"));
    let read = service.inspect(&encrypted, CONTEXT).await;
    assert_eq!((read.plain_text(), read.state()), ("ssh-rsa-test-private-key-material", SecretState::Current));
    // A fresh nonce every time.
    assert_ne!(encrypted, service.encrypt("ssh-rsa-test-private-key-material", CONTEXT).await.unwrap());
    assert!(!service.is_externally_managed());
}

#[tokio::test]
async fn a_value_written_under_the_old_key_still_reads_and_says_so() {
    let written = service(Some(&previous()), &[]).encrypt("deployment key", CONTEXT).await.unwrap();
    let read = service(Some(&current()), &[&previous()]).inspect(&written, CONTEXT).await;
    assert_eq!((read.plain_text(), read.state()), ("deployment key", SecretState::PreviousKey));
}

#[tokio::test]
async fn the_current_key_is_never_reported_as_previous_even_when_listed_twice() {
    let service = service(Some(&current()), &[&format!(" {} ", current()), &previous()]);
    let written = service.encrypt("secret", CONTEXT).await.unwrap();
    assert_eq!(service.inspect(&written, CONTEXT).await.state(), SecretState::Current);
    // A previous key written in its other spelling is the same key, and is dropped too.
    let url_safe = current().replace('+', "-").replace('/', "_");
    let respelled = service_with(&current(), &[&url_safe, &previous()]);
    let old = self::service(Some(&previous()), &[]).encrypt("old", CONTEXT).await.unwrap();
    assert_eq!(respelled.inspect(&old, CONTEXT).await.state(), SecretState::PreviousKey);
}

fn service_with(current: &str, previous: &[&str]) -> Encryption {
    service(Some(current), previous)
}

#[tokio::test]
async fn a_previous_key_is_trimmed_as_the_configuration_record_trims_it() {
    // `EncryptionProperties` trims each previous key: a passphrase listed with spaces is the passphrase.
    let passphrase = "a previous passphrase, invented";
    let written = service(Some(passphrase), &[]).encrypt("old", CONTEXT).await.unwrap();
    let read = service(Some(&current()), &[&format!("  {passphrase}\t")]).inspect(&written, CONTEXT).await;
    assert_eq!((read.plain_text(), read.state()), ("old", SecretState::PreviousKey));
    // While the current key is taken as it is set: its spaces are part of a passphrase.
    let spaced = service(Some(&format!(" {passphrase} ")), &[]).encrypt("new", CONTEXT).await.unwrap();
    assert_eq!(service(Some(passphrase), &[]).inspect(&spaced, CONTEXT).await.state(), SecretState::Unreadable);
}

#[tokio::test]
async fn vault_with_a_blank_token_starts_and_refuses_to_write_as_without_a_key() {
    let config = EncryptionConfig {
        key: Some(Secret::new(current())),
        kms_type: Some("vault".to_owned()),
        vault_endpoint: Some("https://vault.invalid".to_owned()),
        vault_token: Some(Secret::new(" ")),
        ..EncryptionConfig::default()
    };
    let service = Encryption::new(&config, door()).unwrap();
    assert!(!service.is_configured() && service.is_externally_managed());
    assert_eq!(service.encrypt("x", CONTEXT).await, Err(EncryptionError::MissingKey));
}

#[tokio::test]
async fn a_value_relocated_to_another_row_does_not_read() {
    let service = service(Some(&current()), &[]);
    let encrypted = service.encrypt("deployment key", CONTEXT).await.unwrap();
    assert_eq!(service.inspect(&encrypted, "ssh_key:8").await.state(), SecretState::Unreadable);
    assert_eq!(service.inspect(&encrypted, "").await.state(), SecretState::Unreadable, "nor without a context");
}

#[tokio::test]
async fn with_no_key_configured_reading_keeps_working_and_writing_refuses() {
    let written = service(Some(&current()), &[]).encrypt("deployment key", CONTEXT).await.unwrap();
    let unconfigured = service(None, &[&current()]);
    assert!(!unconfigured.is_configured());
    assert_eq!(unconfigured.inspect(&written, CONTEXT).await.plain_text(), "deployment key");
    assert_eq!(unconfigured.encrypt("new secret", CONTEXT).await, Err(EncryptionError::MissingKey));
    // A blank key is no key.
    assert!(!service(Some(" \t"), &[]).is_configured());
}

#[tokio::test]
async fn an_empty_value_needs_no_key() {
    assert_eq!(service(None, &[]).encrypt("", CONTEXT).await.unwrap(), "");
}

#[tokio::test]
async fn an_unreadable_value_yields_no_plain_text() {
    let read = service(Some(&current()), &[]).inspect("v2:not-even-base64", CONTEXT).await;
    assert_eq!((read.plain_text(), read.state()), ("", SecretState::Unreadable));
}

#[test]
fn asking_for_vault_without_credentials_refuses_to_start() {
    let vault = |endpoint: Option<&str>, token: Option<&str>| EncryptionConfig {
        key: Some(Secret::new(current())),
        kms_type: Some("vault".to_owned()),
        vault_endpoint: endpoint.map(str::to_owned),
        vault_token: token.map(Secret::new),
        ..EncryptionConfig::default()
    };
    let refused = Encryption::new(&vault(None, Some("s.token")), door()).unwrap_err();
    assert!(refused.0.contains("no endpoint was provided"), "{refused}");
    let refused = Encryption::new(&vault(Some("https://vault.invalid"), None), door()).unwrap_err();
    assert!(refused.0.contains("no token was provided"), "{refused}");
}

#[test]
fn choosing_local_encryption_or_naming_another_kms_is_not_an_error() {
    // The refusal is about `vault` specifically: a deployment that never asked for a KMS keeps starting — and one
    // that named a KMS Vectispire does not have gets the local one, as in Java.
    for kms in [None, Some("local"), Some("LOCAL"), Some("aws")] {
        let config = EncryptionConfig {
            key: Some(Secret::new(current())),
            kms_type: kms.map(str::to_owned),
            ..EncryptionConfig::default()
        };
        let service = Encryption::new(&config, door()).unwrap();
        assert!(service.is_configured() && !service.is_externally_managed(), "{kms:?}");
    }
}

#[test]
fn the_configuration_and_the_errors_print_no_secret() {
    let config = EncryptionConfig {
        key: Some(Secret::new("a-key-that-must-not-print")),
        vault_token: Some(Secret::new("a-token-that-must-not-print")),
        ..EncryptionConfig::default()
    };
    let printed = format!("{config:?} {:?}", Encryption::new(&config, door()).unwrap());
    assert!(!printed.contains("must-not-print"), "{printed}");
}

#[tokio::test]
async fn the_decrypted_value_prints_no_plain_text() {
    let service = service(Some(&current()), &[]);
    let read = service.inspect(&service.encrypt("must-not-print", CONTEXT).await.unwrap(), CONTEXT).await;
    assert!(!format!("{read:?}").contains("must-not-print"));
}

/// `EncryptionKeyFileTest.theFileFormIsTheSameKey`, through the chain `EncryptionKeyFileDatabaseTest` covers: the
/// variable an operator sets, read by the runtime's configuration, handed to the service.
#[tokio::test]
async fn a_key_from_a_file_encrypts_what_the_same_key_in_a_variable_decrypts() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("key");
    std::fs::write(&file, format!("{}\n", current())).unwrap();
    let path = file.to_str().unwrap().to_owned();
    // `ENCRYPTION_KEY` unset is an empty string in the yaml, and is not a second source.
    let environment = Environment::of([("ENCRYPTION_KEY_FILE", path.as_str()), ("ENCRYPTION_KEY", "")], []);
    let (settings, _) = vectispire_cp_runtime::Settings::load(&environment).unwrap();
    let from_file = Encryption::new(
        &EncryptionConfig {
            key: settings.encryption.key.clone(),
            previous_keys: settings.encryption.previous_keys.clone(),
            ..EncryptionConfig::default()
        },
        door(),
    )
    .unwrap();
    assert!(from_file.is_configured());
    let written = from_file.encrypt("a private key", &private_key_context("1")).await.unwrap();
    // CURRENT, not PREVIOUS_KEY: the file supplied the current key.
    assert_eq!(from_file.inspect(&written, &private_key_context("1")).await.state(), SecretState::Current);
    let from_variable = service(Some(&current()), &[]);
    assert_eq!(from_variable.inspect(&written, &private_key_context("1")).await.plain_text(), "a private key");
}

// ------------------------------------------------------------------------------------------------- Vault

fn vault_service(stub: &Stub) -> Encryption {
    Encryption::new(
        &EncryptionConfig {
            key: Some(Secret::new(current())),
            kms_type: Some("vault".to_owned()),
            vault_endpoint: Some(stub.endpoint()),
            vault_token: Some(Secret::new("vault-token-xyz")),
            vault_key_name: Some("vectispire".to_owned()),
            vault_mount_path: Some("transit".to_owned()),
            ..EncryptionConfig::default()
        },
        door(),
    )
    .unwrap()
}

#[tokio::test]
async fn encrypts_and_decrypts_through_transit_asking_for_the_key_once() {
    use base64::Engine;
    let plain = base64::engine::general_purpose::STANDARD.encode("decrypted-content");
    let stub = Stub::start(vec![
        ("/v1/transit/keys/", 200, r#"{"data": {"derived": true}}"#.to_owned()),
        ("/v1/transit/encrypt/", 200, r#"{"data": {"ciphertext": "vault:v1:8d7f6e5a4b3c"}}"#.to_owned()),
        ("/v1/transit/decrypt/", 200, format!(r#"{{"data": {{"plaintext": "{plain}"}}}}"#)),
    ])
    .await;
    let service = vault_service(&stub);
    assert!(service.is_externally_managed());
    assert_eq!(service.encrypt("my-secret-token", "ctx:1").await.unwrap(), "vault:v1:8d7f6e5a4b3c");
    assert_eq!(service.encrypt("my-secret-token", "ctx:1").await.unwrap(), "vault:v1:8d7f6e5a4b3c");
    let read = service.inspect("vault:v1:8d7f6e5a4b3c", "ctx:1").await;
    assert_eq!((read.plain_text(), read.state()), ("decrypted-content", SecretState::Current));
    let keys = stub.requests().iter().filter(|request| request.path.contains("/keys/")).count();
    assert_eq!(keys, 1, "Vault's definite answer is kept");
    assert!(Encryption::is_ciphertext("vault:v1:8d7f6e5a4b3c"));
}

#[tokio::test]
async fn falls_back_to_local_keys_for_a_ciphertext_vault_did_not_write() {
    let stub = Stub::start(Vec::new()).await;
    let written = service(Some(&current()), &[]).encrypt("legacy-secret", "ctx:legacy").await.unwrap();
    let read = vault_service(&stub).inspect(&written, "ctx:legacy").await;
    assert_eq!(read.plain_text(), "legacy-secret");
    assert!(stub.requests().is_empty(), "a local ciphertext is not sent to Vault");
}

#[tokio::test]
async fn refuses_to_encrypt_under_a_key_that_is_not_derived_but_still_decrypts() {
    use base64::Engine;
    let kept = base64::engine::general_purpose::STANDARD.encode("kept");
    let stub = Stub::start(vec![
        ("/v1/transit/keys/", 200, r#"{"data": {"derived": false}}"#.to_owned()),
        ("/v1/transit/decrypt/", 200, format!(r#"{{"data": {{"plaintext": "{kept}"}}}}"#)),
    ])
    .await;
    let service = vault_service(&stub);
    let refused = service.encrypt("my-secret-token", "ctx:1").await.unwrap_err();
    assert!(refused.to_string().contains("derived=true"), "{refused}");
    assert!(!stub.requests().iter().any(|request| request.path.contains("/encrypt/")));
    // Rather than locking the deployment out of what an ordinary key already holds.
    assert_eq!(service.inspect("vault:v1:8d7f6e5a4b3c", "ctx:1").await.plain_text(), "kept");
    assert_eq!(service.inspect("vault:v1:8d7f6e5a4b3c", "ctx:1").await.plain_text(), "kept");
}

#[tokio::test]
async fn an_address_the_guard_refuses_is_never_reached() {
    // The guard's reserved endpoints are the control plane's own ports: Vault named on one of them is refused
    // before any connection, and the refusal is the guard's.
    let stub = Stub::start(Vec::new()).await;
    let config = EncryptionConfig {
        key: Some(Secret::new(current())),
        kms_type: Some("vault".to_owned()),
        vault_endpoint: Some(stub.endpoint()),
        vault_token: Some(Secret::new("s.stub")),
        ..EncryptionConfig::default()
    };
    let guarded = support::vault::reserved_door(stub.port);
    let service = Encryption::new(&config, guarded).unwrap();
    let refused = service.encrypt("x", "").await.unwrap_err();
    assert!(matches!(refused, EncryptionError::UnsafeUrl(_)), "{refused:?}");
    assert!(stub.requests().is_empty());
}

fn start(key: &str, previous: &[&str]) -> Result<Encryption, String> {
    Encryption::new(
        &EncryptionConfig {
            key: Some(Secret::new(key)),
            previous_keys: previous.iter().map(|key| Secret::new(*key)).collect(),
            ..EncryptionConfig::default()
        },
        door(),
    )
    .map_err(|refused| refused.to_string())
}

/// `EncryptionService.refuseAWeakCurrentKey`'s sentence, which the operator reads at the failed start.
const ADVICE: &str = ". Every secret Vectispire stores is sealed under this key. Generate one with `openssl rand -base64 \
32`. If this installation already stores secrets under the refused value, rotate rather than replace it: set the \
generated key as ENCRYPTION_KEY (or ENCRYPTION_KEY_FILE), the refused value in VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS (or \
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE), restart, and follow the key rotation procedure (docs/en/KEY_ROTATION.md) \
until /actuator/encryption reports the rotation finished.";

#[test]
fn a_placeholder_key_stops_the_start_whatever_its_spelling() {
    // The composition's template shipped CHANGE_ME, and Compose refuses only an empty value: an instance started on
    // it sealed every secret under a key derivable from the public repository.
    for placeholder in [
        "CHANGE_ME",
        "changeme",
        "change-me",
        " Change Me ",
        "<replace me>",
        "CHANGE_ME_generate_with_openssl_rand_base64_32",
        "Put-Your-Key-Here, then restart the instance",
        // Compatibility forms fold to the word under NFKC: a full-width spelling is still the template's.
        "ＣＨＡＮＧＥ＿ＭＥ",
        // A mark between the letters is no letter (`\p{L}`) — though Unicode calls it alphabetic — and goes with the
        // separators.
        "change\u{0345}me-and-a-long-enough-tail",
    ] {
        assert_eq!(
            start(placeholder, &[]).unwrap_err(),
            format!("ENCRYPTION_KEY is refused: it is a template's placeholder, published with the template{ADVICE}"),
            "{placeholder}"
        );
    }
}

#[test]
fn a_short_passphrase_stops_the_start_and_the_message_does_not_quote_it() {
    let refused = start("Summer2026!", &[]).unwrap_err();
    assert_eq!(
        refused,
        format!(
            "ENCRYPTION_KEY is refused: it is a passphrase of 11 characters, and one shorter than 20 is a guess away \
             for whoever holds a copy of the database{ADVICE}"
        )
    );
    assert!(!refused.contains("Summer2026!"));
    assert!(start(&"a".repeat(19), &[]).unwrap_err().contains("19 characters"));
    // Counted in code points, as `codePointCount`: nineteen keys are thirty-eight UTF-16 units and still nineteen.
    assert!(start(&"🔑".repeat(19), &[]).unwrap_err().contains("19 characters"));
    // Trimmed first, as Java trims it.
    assert!(start(&format!("  {}  ", "a".repeat(19)), &[]).unwrap_err().contains("19 characters"));
}

#[tokio::test]
async fn a_long_passphrase_and_a_generated_key_keep_working() {
    let passphrase = "correct horse battery staple";
    let written = start(passphrase, &[]).unwrap().encrypt("deployment key", CONTEXT).await.unwrap();
    assert_eq!(start(passphrase, &[]).unwrap().inspect(&written, CONTEXT).await.state(), SecretState::Current);
    assert!(start(&"b".repeat(vectispire_cp_crypto::MIN_PASSPHRASE_LENGTH), &[]).unwrap().is_configured());
    // An exact 32-byte key is no passphrase: its length is not counted.
    assert!(start(&current(), &[]).unwrap().is_configured());
    assert!(start("q4xqqqvpzWYvqmrtPQ2yVi5MsL9tkal/2cFuqlRG2HE", &[]).unwrap().is_configured());
    // No key at all is not a weak key: it starts, and refuses to write.
    assert!(!service(None, &[]).is_configured());
}

#[tokio::test]
async fn a_refused_key_still_opens_as_a_previous_one_so_the_rotation_can_read_what_it_sealed() {
    // What an installation started on the placeholder holds: values sealed under it. Refusing it among the previous
    // keys would strand them; the rotation is how they leave it.
    let sealed = Encryption::with_random(
        &EncryptionConfig { key: Some(Secret::new("CHANGE_ME")), ..EncryptionConfig::default() },
        door(),
        Box::new(rand_core::OsRng),
    )
    .unwrap()
    .encrypt("deployment key", CONTEXT)
    .await
    .unwrap();
    let rotating = start(&current(), &["CHANGE_ME", "short"]).unwrap();
    let read = rotating.inspect(&sealed, CONTEXT).await;
    assert_eq!((read.plain_text(), read.state()), ("deployment key", SecretState::PreviousKey));
    assert_eq!(service(None, &["CHANGE_ME"]).inspect(&sealed, CONTEXT).await.plain_text(), "deployment key");
}
