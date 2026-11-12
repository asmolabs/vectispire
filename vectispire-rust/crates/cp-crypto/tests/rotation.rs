//! `SigningKeyServiceTest`'s rotation cases, on real servers: a document signed before a rotation still verifies,
//! a revoked key verifies nothing, and the record of published keys is Vectispire's only when Vectispire sealed it.
//!
//! The queries are `vectispire-cp-settings`' (`internal_value`, `store_internal_if_absent`, `reseal_internal`),
//! checked there; this module adds none.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use base64::Engine as _;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use support::database::Migrated;
use support::labelled::standard_key;
use support::vault::door;
use vectispire_cp_crypto::{
    Clock, Encryption, EncryptionConfig, KNOWN_KEYS, KNOWN_KEYS_CONTEXT, KeyStatus, SEALED_KNOWN_KEYS, STORED_KEY,
    SecretState, SigningConfig, SigningError, SigningKeys,
};
use vectispire_cp_db::Engine;
use vectispire_cp_settings::Settings;
use vectispire_domain::instant::Instant;
use vectispire_domain::secret::Secret;

const PAYLOAD: &[u8] = br#"{"status":"passed"}"#;

fn encryption_with(key: &str, previous: &[&str]) -> Arc<Encryption> {
    let config = EncryptionConfig {
        key: Some(Secret::new(key)),
        previous_keys: previous.iter().map(|key| Secret::new(*key)).collect(),
        ..EncryptionConfig::default()
    };
    Arc::new(Encryption::new(&config, door()).unwrap())
}

fn encryption() -> Arc<Encryption> {
    encryption_with(&standard_key("rotation-test:encryption-key"), &[])
}

fn at(text: &str) -> Instant {
    Instant::parse_java(text).unwrap()
}

/// A fresh P-256 pair, as `CosignSigner.generateKeyPair`.
fn pair() -> SigningKey {
    SigningKey::random(&mut rand_core::OsRng)
}

fn pem(key: &SigningKey) -> String {
    key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string()
}

fn public_pem(key: &SigningKey) -> String {
    key.verifying_key().to_public_key_pem(LineEnding::LF).unwrap()
}

fn der(key: &SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes())
}

fn id(key: &SigningKey) -> String {
    use sha2::Digest;
    let spki = key.verifying_key().to_public_key_der().unwrap();
    sha2::Sha256::digest(spki.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sign(key: &SigningKey) -> String {
    let signature: DerSignature = key.sign(PAYLOAD);
    base64::engine::general_purpose::STANDARD.encode(signature.as_bytes())
}

/// A line of the record, as an installation writes it.
fn line(key: &SigningKey, active_from: &str, retired_at: &str) -> String {
    format!("{};{active_from};{retired_at};{}", id(key), der(key))
}

async fn keys(settings: &Settings, configured: &str, revoked: &str) -> SigningKeys {
    started(settings, SigningConfig { key: configured, revoked_keys: revoked, adopted_keys: "" }, encryption()).await
}

async fn started(settings: &Settings, config: SigningConfig<'_>, encryption: Arc<Encryption>) -> SigningKeys {
    SigningKeys::start(config, settings.clone(), encryption, Clock::system()).await.unwrap()
}

async fn on(settings: &Settings, configured: &SigningKey, clock: &str) -> SigningKeys {
    let config = SigningConfig { key: &pem(configured), ..SigningConfig::default() };
    SigningKeys::start(config, settings.clone(), encryption(), Clock::fixed(at(clock))).await.unwrap()
}

/// The record as an installation seals it.
async fn seal_record(settings: &Settings, under: &Encryption, lines: &[String]) {
    let sealed = under.encrypt(&lines.join("\n"), KNOWN_KEYS_CONTEXT).await.unwrap();
    assert!(settings.store_internal_if_absent(SEALED_KNOWN_KEYS, &sealed).await.unwrap());
}

async fn open_record(settings: &Settings) -> String {
    let stored = settings.internal_value(SEALED_KNOWN_KEYS).await.unwrap().unwrap();
    encryption().inspect(&stored, KNOWN_KEYS_CONTEXT).await.plain_text().to_owned()
}

async fn listed(keys: &SigningKeys) -> Vec<(String, KeyStatus)> {
    keys.published_keys().await.unwrap().into_iter().map(|k| (k.key_id, k.status)).collect()
}

async fn a_rotation_keeps_the_past_verifiable(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    // The installation's first key: generated and stored, as on every deployment that set none.
    let generated = keys(&settings, "", "").await;
    let old_id = generated.key_id().await.unwrap();
    let before = generated.sign(PAYLOAD).await.unwrap();

    // The rotation: a key configured, and a restart.
    let next = pair();
    let rotated = keys(&settings, &pem(&next), "").await;
    let after = rotated.sign(PAYLOAD).await.unwrap();

    assert_ne!(rotated.key_id().await.unwrap(), old_id);
    assert!(rotated.verify(PAYLOAD, &after).await.unwrap());
    // It stopped verifying the moment the key changed: it was checked against the active key and nothing else.
    assert!(rotated.verify(PAYLOAD, &before).await.unwrap());
    let verdict = rotated.verify_with(PAYLOAD, &before, None).await.unwrap();
    assert_eq!(
        (verdict.valid, verdict.key_id.as_deref(), verdict.key_status),
        (true, Some(old_id.as_str()), Some(KeyStatus::Retired))
    );
    assert!(
        verdict.message.starts_with("Signature valid: signed with a previous Vectispire signing key, replaced on ")
    );
    assert!(verdict.message.ends_with(". The key was retired, not revoked: what it signed remains authentic."));

    assert_eq!(listed(&rotated).await, vec![(id(&next), KeyStatus::Active), (old_id.clone(), KeyStatus::Retired)]);
    // What a consumer does: fetch the key the document names, and check with it alone.
    let old_pem = rotated.published_key(&old_id.to_uppercase()).await.unwrap().unwrap().public_key_pem;
    assert!(rotated.verify_with(PAYLOAD, &before, Some(&old_pem)).await.unwrap().valid);
    assert!(!rotated.verify_with(PAYLOAD, &after, Some(&old_pem)).await.unwrap().valid);

    // And it survives the next restart, which has nothing left to reconcile.
    let again = keys(&settings, &pem(&next), "").await;
    assert!(again.verify(PAYLOAD, &before).await.unwrap());
    assert_eq!(again.published_keys().await.unwrap().len(), 2);
    // The public halves are not readable in the row.
    let sealed = settings.internal_value(SEALED_KNOWN_KEYS).await.unwrap().unwrap();
    assert!(sealed.starts_with("v2:") && !sealed.contains(&old_id), "{sealed}");
}

async fn a_configured_key_replaced_stays_published_with_its_dates(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let (monday, friday) = ("2026-10-26T09:00:00Z", "2026-10-30T09:00:00Z");
    let (first, second) = (pair(), pair());
    let signed = on(&settings, &first, monday).await.sign(PAYLOAD).await.unwrap();

    let on_second = on(&settings, &second, friday).await;
    let retired = on_second.published_key(&id(&first)).await.unwrap().unwrap();
    assert_eq!(
        (retired.status, retired.active_from, retired.retired_at),
        (KeyStatus::Retired, Some(at(monday)), Some(at(friday)))
    );
    let active = on_second.published_key(&id(&second)).await.unwrap().unwrap();
    assert_eq!((active.active_from, active.retired_at), (Some(at(friday)), None));
    assert!(on_second.verify(PAYLOAD, &signed).await.unwrap());
    // No generated key appeared along the way: both were configured.
    assert_eq!(settings.internal_value(STORED_KEY).await.unwrap(), None);
    // The record's lines, as Java writes them.
    assert_eq!(
        open_record(&settings).await,
        format!("{}\n{}", line(&first, monday, friday), line(&second, friday, "-"))
    );
}

async fn a_revoked_key_verifies_nothing_and_cannot_sign(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let compromised = pair();
    let signed = keys(&settings, &pem(&compromised), "").await.sign(PAYLOAD).await.unwrap();

    let rotated = keys(&settings, &pem(&pair()), &format!(" {} ", id(&compromised).to_uppercase())).await;
    // Whoever holds a compromised key signs whatever they like with it; a match proves nothing.
    assert!(!rotated.verify(PAYLOAD, &signed).await.unwrap());
    let verdict = rotated.verify_with(PAYLOAD, &signed, None).await.unwrap();
    assert_eq!(
        (verdict.valid, verdict.key_id.as_deref(), verdict.key_status, verdict.message.as_str()),
        (
            false,
            Some(id(&compromised).as_str()),
            Some(KeyStatus::Revoked),
            "The signature matches a Vectispire signing key that has been revoked: do not trust this document."
        )
    );
    let supplied = rotated.verify_with(PAYLOAD, &signed, Some(&public_pem(&compromised))).await.unwrap();
    assert_eq!((supplied.valid, supplied.vectispire_key), (false, true));
    assert_eq!(rotated.published_key(&id(&compromised)).await.unwrap().unwrap().status, KeyStatus::Revoked);

    // The key that would sign, revoked: refused at start, with the reason.
    let refused = SigningKeys::start(
        SigningConfig { key: &pem(&compromised), revoked_keys: &id(&compromised), adopted_keys: "" },
        settings.clone(),
        encryption(),
        Clock::system(),
    )
    .await
    .unwrap_err();
    assert!(matches!(refused, SigningError::Revoked(_)), "{refused:?}");
    assert_eq!(
        refused.to_string(),
        format!(
            "The document signing key {} is listed in vectispire.signing.revoked-keys and cannot sign. Configure a new \
             key in vectispire.signing.key.",
            id(&compromised)
        )
    );
}

async fn a_revoked_generated_key_is_refused_at_start(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let generated_id = keys(&settings, "", "").await.key_id().await.unwrap();

    // It started, and every export that needed the key answered 500 — a revocation read as an outage.
    let refused = SigningKeys::start(
        SigningConfig { revoked_keys: &generated_id, ..SigningConfig::default() },
        settings.clone(),
        encryption(),
        Clock::system(),
    )
    .await
    .unwrap_err();
    assert!(refused.to_string().contains("vectispire.signing.revoked-keys"), "{refused}");
    // A configured key in front of it signs, and the revoked one stays published as revoked.
    let rotated = keys(&settings, &pem(&pair()), &generated_id).await;
    assert_eq!(rotated.published_key(&generated_id).await.unwrap().unwrap().status, KeyStatus::Revoked);
    // A revocation naming another key leaves the generated one signing.
    assert_eq!(keys(&settings, "", &"0".repeat(64)).await.key_id().await.unwrap(), generated_id);
}

async fn a_rolling_restart_publishes_one_list(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let (old, next) = (pair(), pair());
    on(&settings, &old, "2026-10-26T09:00:00Z").await.sign(PAYLOAD).await.unwrap();
    // Started on Tuesday with the old key, and has signed nothing yet when the rotation comes.
    let not_yet_restarted = on(&settings, &old, "2026-10-27T09:00:00Z").await;
    let restarted = on(&settings, &next, "2026-10-30T09:00:00Z").await;
    restarted.sign(PAYLOAD).await.unwrap();

    let signed_in_the_window = not_yet_restarted.sign(PAYLOAD).await.unwrap();

    // The old instance called its own key active and the new one retired: two lists behind one load balancer.
    let expected = vec![(id(&next), KeyStatus::Active), (id(&old), KeyStatus::Retired)];
    let third = keys(&settings, &pem(&next), "").await;
    for instance in [&not_yet_restarted, &restarted, &third] {
        assert_eq!(listed(instance).await, expected);
        assert_eq!(instance.active_public_key_pem().await.unwrap(), public_pem(&next));
    }
    // What the old instance signed in the window is a retired key's, and still authentic.
    let verdict = restarted.verify_with(PAYLOAD, &signed_in_the_window, None).await.unwrap();
    assert_eq!(
        (verdict.valid, verdict.key_id.as_deref(), verdict.key_status),
        (true, Some(id(&old).as_str()), Some(KeyStatus::Retired))
    );
    assert!(verdict.message.contains("retired, not revoked") && !verdict.message.contains("before that date"));
    assert_eq!(
        not_yet_restarted.verify_with(PAYLOAD, &signed_in_the_window, None).await.unwrap().key_status,
        Some(KeyStatus::Retired)
    );
}

async fn publishes_without_its_own_key(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    // ENCRYPTION_KEY lost for the generated key: it cannot be read, and signing is refused. The routes that publish
    // the keys must still answer — the revocation list unreadable when it counts would be worse.
    let (recorded, compromised) = (pair(), pair());
    seal_record(
        &settings,
        &encryption(),
        &[
            line(&recorded, "2026-10-01T00:00:00Z", "-"),
            line(&compromised, "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z"),
        ],
    )
    .await;
    assert!(
        settings
            .store_internal_if_absent(STORED_KEY, "v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .unwrap()
    );

    let service = keys(&settings, "", &id(&compromised)).await;
    assert_eq!(
        listed(&service).await,
        vec![(id(&recorded), KeyStatus::Active), (id(&compromised), KeyStatus::Revoked)]
    );
    assert_eq!(service.active_public_key_pem().await.unwrap(), public_pem(&recorded));
    assert!(service.verify(PAYLOAD, &sign(&recorded)).await.unwrap());
    assert!(matches!(service.sign(PAYLOAD).await, Err(SigningError::Unreadable)));
}

async fn a_rotation_rolled_back(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let generated_id = keys(&settings, "", "").await.key_id().await.unwrap();
    let signed_by_next = keys(&settings, &pem(&pair()), "").await.sign(PAYLOAD).await.unwrap();

    // The configured key removed: the stored one signs again.
    let back = keys(&settings, "", "").await;
    assert_eq!(back.key_id().await.unwrap(), generated_id);
    let statuses: Vec<KeyStatus> = listed(&back).await.into_iter().map(|(_, status)| status).collect();
    assert_eq!(statuses, vec![KeyStatus::Active, KeyStatus::Retired]);
    assert!(back.verify(PAYLOAD, &signed_by_next).await.unwrap());
    // Active again from now: a key brought back still showing its retirement would say it signed nothing after.
    assert_eq!(back.published_key(&generated_id).await.unwrap().unwrap().retired_at, None);
}

async fn a_key_from_before_the_record_is_published_at_the_first_rotation(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    // The 0.11 shape: a stored key, signed with, and no record. The first start after the upgrade may already carry
    // a configured key — the generated one must not vanish.
    let old = pair();
    let sealed = encryption().encrypt(&pem(&old), "internal:document_signing_key").await.unwrap();
    assert!(settings.store_internal_if_absent(STORED_KEY, &sealed).await.unwrap());

    let rotated = keys(&settings, &pem(&pair()), "").await;
    let published = rotated.published_key(&id(&old)).await.unwrap().unwrap();
    assert_eq!((published.status, published.active_from), (KeyStatus::Retired, None));
    assert!(rotated.verify(PAYLOAD, &sign(&old)).await.unwrap());
}

async fn a_recorded_id_is_recomputed(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    // Whoever edits a restored dump could list a key of theirs under one of Vectispire's ids.
    let (honest, forged) = (pair(), pair());
    let claimed = id(&pair());
    let forged_line = format!("{claimed};2026-10-01T00:00:00Z;2026-10-02T00:00:00Z;{}", der(&forged));
    seal_record(
        &settings,
        &encryption(),
        &[
            line(&honest, "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z"),
            forged_line.clone(),
            "not a line at all".to_owned(),
        ],
    )
    .await;

    let service = keys(&settings, &pem(&pair()), "").await;
    assert_eq!(service.published_key(&claimed).await.unwrap(), None);
    assert_eq!(service.published_key(&id(&forged)).await.unwrap(), None);
    let verdict = service.verify_with(PAYLOAD, &sign(&forged), None).await.unwrap();
    assert_eq!((verdict.valid, verdict.key_id, verdict.key_status), (false, None, None));
    assert_eq!(verdict.message, "Signature does not match any of Vectispire's signing keys for this payload.");
    // One bad line hides itself, not the record.
    let ids: Vec<String> = listed(&service).await.into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, vec![service.key_id().await.unwrap(), id(&honest)]);
    assert!(service.verify(PAYLOAD, &sign(&honest)).await.unwrap());
    // The registration that rewrote the row kept the refused lines for whoever investigates.
    let record = open_record(&settings).await;
    assert!(record.contains(&forged_line) && record.contains("not a line at all"), "{record}");
}

async fn a_key_written_into_the_record_is_not_vectispire_s(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let generated = keys(&settings, "", "").await;
    let signed_before = generated.sign(PAYLOAD).await.unwrap();
    let next = pair();
    let running = keys(&settings, &pem(&next), "").await;
    running.sign(PAYLOAD).await.unwrap();
    let sealed = settings.internal_value(SEALED_KNOWN_KEYS).await.unwrap().unwrap();

    // The record replaced by the same lines in the clear, with one more key.
    let planted = pair();
    let clear =
        format!("{}\n{}", open_record(&settings).await, line(&planted, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"));
    assert!(settings.reseal_internal(SEALED_KNOWN_KEYS, &sealed, &clear).await.unwrap());
    let forged = sign(&planted);

    let restarted = keys(&settings, &pem(&next), "").await;
    for instance in [&running, &restarted] {
        assert!(!instance.verify(PAYLOAD, &forged).await.unwrap());
        assert!(!instance.verify_with(PAYLOAD, &forged, Some(&public_pem(&planted))).await.unwrap().vectispire_key);
        assert_eq!(instance.published_key(&id(&planted)).await.unwrap(), None);
        // Refused whole: the active key alone is published, by the instance that signs with it.
        let ids: Vec<String> = listed(instance).await.into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, vec![instance.key_id().await.unwrap()]);
        assert!(!instance.verify(PAYLOAD, &signed_before).await.unwrap());
    }
    // And never overwritten.
    assert_eq!(settings.internal_value(SEALED_KNOWN_KEYS).await.unwrap().as_deref(), Some(clear.as_str()));
}

async fn a_record_sealed_for_another_row_is_refused(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let planted = pair();
    let sealed = encryption()
        .encrypt(&line(&planted, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"), "internal:document_signing_key")
        .await
        .unwrap();
    assert!(settings.store_internal_if_absent(SEALED_KNOWN_KEYS, &sealed).await.unwrap());

    let service = keys(&settings, &pem(&pair()), "").await;
    assert!(!service.verify(PAYLOAD, &sign(&planted)).await.unwrap());
    assert_eq!(service.published_key(&id(&planted)).await.unwrap(), None);
}

async fn the_unsealed_record_is_not_trusted(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let (honest, planted) = (pair(), pair());
    let unsealed = format!(
        "{}\n{}",
        line(&honest, "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z"),
        line(&planted, "2026-09-15T00:00:00Z", "2026-10-01T00:00:00Z")
    );
    assert!(settings.store_internal_if_absent(KNOWN_KEYS, &unsealed).await.unwrap());
    let configured = pem(&pair());

    // No word from the operator: the row is anybody's who can write the database.
    let unvouched = keys(&settings, &configured, "").await;
    assert!(!unvouched.verify(PAYLOAD, &sign(&planted)).await.unwrap());
    assert!(!unvouched.verify(PAYLOAD, &sign(&honest)).await.unwrap());
    let ids: Vec<String> = listed(&unvouched).await.into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, vec![unvouched.key_id().await.unwrap()]);

    // The operator vouches for one key, by its id, in the configuration: sealed into the record at that start.
    let vouched = started(
        &settings,
        SigningConfig {
            key: &configured,
            revoked_keys: "",
            adopted_keys: &format!(" {} ", id(&honest).to_uppercase()),
        },
        encryption(),
    )
    .await;
    let verdict = vouched.verify_with(PAYLOAD, &sign(&honest), None).await.unwrap();
    assert_eq!((verdict.valid, verdict.key_status), (true, Some(KeyStatus::Retired)));
    assert!(!vouched.verify(PAYLOAD, &sign(&planted)).await.unwrap());
    assert_eq!(vouched.published_key(&id(&planted)).await.unwrap(), None);

    // Sealed, not remembered: the next start, without the setting, still publishes it.
    let restarted = keys(&settings, &configured, "").await;
    let ids: Vec<String> = listed(&restarted).await.into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, vec![restarted.key_id().await.unwrap(), id(&honest)]);
    assert!(restarted.verify(PAYLOAD, &sign(&honest)).await.unwrap());
    // The unsealed row is read, never rewritten.
    assert_eq!(settings.internal_value(KNOWN_KEYS).await.unwrap(), Some(unsealed));
}

async fn a_running_instance_adopts_nothing(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let planted = pair();
    let running = started(
        &settings,
        SigningConfig { key: &pem(&pair()), revoked_keys: "", adopted_keys: &id(&planted) },
        encryption(),
    )
    .await;
    running.sign(PAYLOAD).await.unwrap();

    let row = line(&planted, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z");
    assert!(settings.store_internal_if_absent(KNOWN_KEYS, &row).await.unwrap());
    assert!(!running.verify(PAYLOAD, &sign(&planted)).await.unwrap());
    assert_eq!(running.published_key(&id(&planted)).await.unwrap(), None);
}

async fn the_keys_sealed_under_a_previous_encryption_key_are_resealed(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let (old, new) = ("rotation-test-old-passphrase-0123456789", "rotation-test-new-passphrase-0123456789");
    let before = encryption_with(old, &[]);
    let after = encryption_with(new, &[old]);
    // The private key, sealed under the old ENCRYPTION_KEY.
    let generated = pair();
    let sealed_key = before.encrypt(&pem(&generated), "internal:document_signing_key").await.unwrap();
    assert!(settings.store_internal_if_absent(STORED_KEY, &sealed_key).await.unwrap());
    // And the record, with a key it replaced.
    let retired = pair();
    seal_record(&settings, &before, &[line(&retired, "2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z")]).await;

    let rotated = started(&settings, SigningConfig::default(), after.clone()).await;
    // The record at start, the private key as it loads.
    let record = settings.internal_value(SEALED_KNOWN_KEYS).await.unwrap().unwrap();
    assert_eq!(after.inspect(&record, KNOWN_KEYS_CONTEXT).await.state(), SecretState::Current);
    assert_eq!(rotated.key_id().await.unwrap(), id(&generated));
    let stored = settings.internal_value(STORED_KEY).await.unwrap().unwrap();
    assert_eq!(after.inspect(&stored, "internal:document_signing_key").await.state(), SecretState::Current);

    // The previous key can go: nothing depends on it any more.
    let without_it = started(&settings, SigningConfig::default(), encryption_with(new, &[])).await;
    assert!(without_it.verify(PAYLOAD, &sign(&retired)).await.unwrap());
    assert_eq!(without_it.key_id().await.unwrap(), id(&generated));
}

macro_rules! on_both_engines {
    ($($name:ident),* $(,)?) => {
        mod mysql {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { if vectispire_cp_db::testing::runs_on(super::Engine::MySql) { super::$name(super::Engine::MySql).await; } })*
        }
        mod postgres {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { if vectispire_cp_db::testing::runs_on(super::Engine::PostgreSql) { super::$name(super::Engine::PostgreSql).await; } })*
        }
    };
}

on_both_engines!(
    a_rotation_keeps_the_past_verifiable,
    a_configured_key_replaced_stays_published_with_its_dates,
    a_revoked_key_verifies_nothing_and_cannot_sign,
    a_revoked_generated_key_is_refused_at_start,
    a_rolling_restart_publishes_one_list,
    publishes_without_its_own_key,
    a_rotation_rolled_back,
    a_key_from_before_the_record_is_published_at_the_first_rotation,
    a_recorded_id_is_recomputed,
    a_key_written_into_the_record_is_not_vectispire_s,
    a_record_sealed_for_another_row_is_refused,
    the_unsealed_record_is_not_trusted,
    a_running_instance_adopts_nothing,
    the_keys_sealed_under_a_previous_encryption_key_are_resealed,
);
