//! The census of the sealed stores (`EncryptionService.sealOf`, `SigningKeyService.census()`): which key each stored
//! value depends on, counted as the rotation procedure reads it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use support::database::Migrated;
use support::labelled::standard_key;
use support::vault::door;
use vectispire_cp_crypto::{
    Encryption, EncryptionCensus, EncryptionConfig, SEALED_KNOWN_KEYS, STORED_KEY, Seal, SealedStore, SigningKeys,
};
use vectispire_cp_db::Engine;
use vectispire_cp_settings::Settings;
use vectispire_domain::secret::Secret;

fn encryption_with(key: &str, previous: &[&str]) -> Arc<Encryption> {
    let config = EncryptionConfig {
        key: Some(Secret::new(key)),
        previous_keys: previous.iter().map(|key| Secret::new(*key)).collect(),
        ..EncryptionConfig::default()
    };
    Arc::new(Encryption::new(&config, door()).unwrap())
}

#[tokio::test]
async fn a_seal_says_which_key_reads_the_value_and_never_counts_an_empty_one() {
    let old = standard_key("census:old");
    let new = standard_key("census:new");
    let before = encryption_with(&old, &[]);
    let after = encryption_with(&new, &[&old]);
    let under_old = before.encrypt("secret", "ctx").await.unwrap();
    let under_new = after.encrypt("secret", "ctx").await.unwrap();

    assert_eq!(after.seal_of(Some(&under_new), "ctx").await, Seal::Current);
    assert_eq!(after.seal_of(Some(&under_old), "ctx").await, Seal::PreviousKey);
    // Bound to its row: the same ciphertext read for another is no key's.
    assert_eq!(after.seal_of(Some(&under_new), "elsewhere").await, Seal::Unreadable);
    assert_eq!(after.seal_of(Some("legacy-token"), "ctx").await, Seal::Clear);
    // `String.trim()` first, as Java: a value padded with blanks is still the ciphertext it holds.
    assert_eq!(after.seal_of(Some(&format!("  {under_new}\n")), "ctx").await, Seal::Current);
    for empty in [None, Some(""), Some(" \t ")] {
        assert_eq!(after.seal_of(empty, "ctx").await, Seal::Empty, "{empty:?}");
    }
}

async fn the_signing_rows_are_counted_under_the_key_that_sealed_them(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let old = standard_key("census:signing:old");

    // Nothing stored yet: two lines, nothing in them.
    let keys = SigningKeys::new("", settings.clone(), encryption_with(&old, &[])).unwrap();
    let lines = keys.census().await.unwrap();
    let names: Vec<&str> = lines.iter().map(|line| line.store.as_str()).collect();
    assert_eq!(names, ["Document signing key", "Published document signing keys"]);
    assert!(lines.iter().all(|line| (line.current, line.previous_key, line.unreadable, line.clear) == (0, 0, 0, 0)));

    // The first signature generates the key and seals the record, both under the key of the day.
    keys.key_id().await.unwrap();
    let lines = keys.census().await.unwrap();
    assert!(lines.iter().all(|line| line.current == 1 && line.previous_key == 0), "{lines:?}");

    // A rotation, before the next start re-seals them: both rows need the previous key.
    let rotated =
        SigningKeys::new("", settings.clone(), encryption_with(&standard_key("census:signing:new"), &[&old])).unwrap();
    let lines = rotated.census().await.unwrap();
    assert!(lines.iter().all(|line| line.current == 0 && line.previous_key == 1), "{lines:?}");
    let report = EncryptionCensus::new(vec![Arc::new(rotated)]).report().await.unwrap();
    assert!(report.starts_with("{\"rotationFinished\":false,"), "{report}");
    assert!(
        settings.internal_value(STORED_KEY).await.unwrap().is_some()
            && settings.internal_value(SEALED_KNOWN_KEYS).await.unwrap().is_some()
    );
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

on_both_engines!(the_signing_rows_are_counted_under_the_key_that_sealed_them);
