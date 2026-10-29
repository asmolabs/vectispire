//! `SigningKeyServiceTest` on real servers, both engines: whether a signature can still be checked tomorrow.
//!
//! Each test builds the keys the way a restart, a second instance or a configured deployment does. The queries
//! are `vectispire-cp-settings`' (`internal_value`, `store_internal_if_absent`), checked there; this module adds
//! none.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use p256::pkcs8::{EncodePrivateKey, LineEnding};
use support::database::Migrated;
use support::labelled::standard_key;
use support::vault::door;
use tokio::sync::Notify;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, KeyStore, STORED_KEY, SigningError, SigningKeys};
use vectispire_cp_db::Engine;
use vectispire_cp_settings::{Settings, SettingsError};
use vectispire_domain::secret::Secret;

const PAYLOAD: &[u8] = br#"{"status":"passed"}"#;

fn encryption(key: Option<&str>) -> Arc<Encryption> {
    Arc::new(
        Encryption::new(&EncryptionConfig { key: key.map(Secret::new), ..EncryptionConfig::default() }, door())
            .unwrap(),
    )
}

fn configured() -> Arc<Encryption> {
    encryption(Some(&standard_key("signing-test:encryption-key")))
}

async fn survives_a_restart(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let first = SigningKeys::new("", settings.clone(), configured()).unwrap();
    let signature = first.sign(PAYLOAD).await.unwrap();

    let after_restart = SigningKeys::new("", settings.clone(), configured()).unwrap();
    assert_eq!(after_restart.key_id().await.unwrap(), first.key_id().await.unwrap());
    assert!(after_restart.verify(PAYLOAD, &signature).await.unwrap());
    // Stored encrypted, never as a PEM anybody reading the table could use.
    let stored = settings.internal_value(STORED_KEY).await.unwrap().unwrap();
    assert!(stored.starts_with("v2:") && !stored.contains("PRIVATE KEY"), "{stored}");
}

/// Forced interleaving: the second instance reads "no key" first, then waits while the first generates, stores and
/// signs, and only then generates and stores its own — which must not replace the first.
async fn two_instances_agree_on_one_key(engine: Engine) {
    struct SlowToStore {
        inner: Settings,
        looked: AtomicBool,
        second_has_looked: Arc<Notify>,
        first_is_signing: Arc<Notify>,
    }
    impl KeyStore for SlowToStore {
        async fn internal_value(&self, key: &str) -> Result<Option<String>, SettingsError> {
            let seen = self.inner.internal_value(key).await;
            if !self.looked.swap(true, Ordering::SeqCst) {
                self.second_has_looked.notify_one();
                self.first_is_signing.notified().await;
            }
            seen
        }
        async fn store_internal_if_absent(&self, key: &str, value: &str) -> Result<bool, SettingsError> {
            self.inner.store_internal_if_absent(key, value).await
        }
    }

    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let (second_has_looked, first_is_signing) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let slow = SlowToStore {
        inner: settings.clone(),
        looked: AtomicBool::new(false),
        second_has_looked: second_has_looked.clone(),
        first_is_signing: first_is_signing.clone(),
    };
    let second = Arc::new(SigningKeys::new("", slow, configured()).unwrap());
    let second_key = tokio::spawn({
        let second = second.clone();
        async move { second.key_id().await.unwrap() }
    });

    second_has_looked.notified().await;
    let first = SigningKeys::new("", settings.clone(), configured()).unwrap();
    let signature = first.sign(PAYLOAD).await.unwrap();
    first_is_signing.notify_one();

    assert_eq!(second_key.await.unwrap(), first.key_id().await.unwrap());
    let after_restart = SigningKeys::new("", settings, configured()).unwrap();
    assert_eq!(after_restart.key_id().await.unwrap(), first.key_id().await.unwrap(), "the stored key is the first's");
    assert!(after_restart.verify(PAYLOAD, &signature).await.unwrap());
    assert!(second.verify(PAYLOAD, &signature).await.unwrap());
}

async fn a_configured_key_publishes_its_own_half_and_stores_nothing(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let key = p256::SecretKey::random(&mut rand_core::OsRng);
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();

    let keys = SigningKeys::new(&pem, settings.clone(), configured()).unwrap();
    assert_eq!(keys.public_key().await.unwrap(), p256::ecdsa::VerifyingKey::from(key.public_key()));
    let signature = keys.sign(PAYLOAD).await.unwrap();
    let published = keys.public_key_pem().await.unwrap();
    assert!(keys.verify_with(PAYLOAD, &signature, Some(&published)).await.unwrap().valid);
    assert_eq!(settings.internal_value(STORED_KEY).await.unwrap(), None);
}

async fn an_unreadable_key_is_refused_and_never_replaced(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let unreadable = "v2:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(settings.store_internal_if_absent(STORED_KEY, unreadable).await.unwrap());

    let keys = SigningKeys::new("", settings.clone(), configured()).unwrap();
    assert!(matches!(keys.sign(PAYLOAD).await, Err(SigningError::Unreadable)));
    // A replacement would have made every document already signed unverifiable.
    assert_eq!(settings.internal_value(STORED_KEY).await.unwrap().as_deref(), Some(unreadable));
}

async fn without_an_encryption_key_nothing_is_signed_and_nothing_stored(engine: Engine) {
    let server = Migrated::start(engine).await;
    let settings = Settings::new(server.connect().await);
    let keys = SigningKeys::new("", settings.clone(), encryption(None)).unwrap();
    let refused = keys.sign(PAYLOAD).await.unwrap_err();
    assert!(matches!(refused, SigningError::MissingKey), "{refused:?}");
    assert_eq!(settings.internal_value(STORED_KEY).await.unwrap(), None);
    // Not kept: once a key is configured, the same instance signs.
    assert!(SigningKeys::new("", settings.clone(), configured()).unwrap().sign(PAYLOAD).await.is_ok());
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
    survives_a_restart,
    two_instances_agree_on_one_key,
    a_configured_key_publishes_its_own_half_and_stores_nothing,
    an_unreadable_key_is_refused_and_never_replaced,
    without_an_encryption_key_nothing_is_signed_and_nothing_stored,
);
