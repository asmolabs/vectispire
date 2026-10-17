//! The store of `t_setting` on real servers, both engines: reads with the catalog's defaults, the writes, and the
//! two that arbitrate between instances.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use support::Migrated;
use vectispire_cp_db::{Engine, Mode};
use vectispire_cp_settings::{Setting, Settings, SettingsError};

/// Reads: the default for an absent row, the stored value even when empty, a removed key ignored by the catalog
/// but present in what is stored.
async fn reads_take_the_row_or_the_catalog_s_default(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let settings = Settings::new(db.clone());
    // The migrations seed none of these.
    assert!(!settings.is_stored(Setting::SastEnabled).await.unwrap());
    assert_eq!(settings.get(Setting::SastEnabled).await.unwrap(), "false", "the default");
    assert!(!settings.is_enabled(Setting::SastEnabled).await.unwrap());
    assert_eq!(settings.as_int(Setting::EolWarnDays).await.unwrap(), 180);

    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    settings.set(&mut tx, Setting::SastEnabled, "true").await.unwrap();
    settings.set(&mut tx, Setting::WebhookUrl, "").await.unwrap();
    settings.set(&mut tx, Setting::EolWarnDays, "not a number").await.unwrap();
    tx.commit().await.unwrap();
    server.sql_as_admin(
        "insert into t_setting (\"key\", value) values ('a_removed_setting', 'kept')"
            .replace(
                '"',
                match engine {
                    Engine::MySql => "`",
                    Engine::PostgreSql => "\"",
                },
            )
            .as_str(),
    );

    assert!(settings.is_enabled(Setting::SastEnabled).await.unwrap());
    assert!(settings.is_stored(Setting::WebhookUrl).await.unwrap());
    assert_eq!(settings.get(Setting::WebhookUrl).await.unwrap(), "", "a cleared field stays cleared");
    assert_eq!(
        settings.as_int(Setting::EolWarnDays).await.unwrap(),
        180,
        "an unreadable row falls back to the default"
    );
    let stored = settings.stored().await.unwrap();
    assert_eq!(stored.get("a_removed_setting").map(String::as_str), Some("kept"));
    let effective = settings.effective().await.unwrap();
    assert_eq!(effective.get("sast_enabled").map(String::as_str), Some("true"));
    assert_eq!(effective.get("enrichment_enabled").map(String::as_str), Some("true"), "a default fills the rest");
    assert_eq!(effective.len(), Setting::ALL.len() + 1, "every catalog key, and the stored removed one");
}

/// Writing the value a row already holds is still a write onto that row — MySQL counts it as found because sqlx
/// asks for found rows, as Connector/J does; without that, the insert that follows would collide.
async fn writing_a_value_twice_updates_the_row(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let settings = Settings::new(db.clone());
    for _ in 0..2 {
        let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
        settings.set(&mut tx, Setting::SlaHighDays, "30").await.unwrap();
        settings.set_internal(&mut tx, "internal.marker", "same").await.unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(settings.get(Setting::SlaHighDays).await.unwrap(), "30");
    assert_eq!(settings.internal_value("internal.marker").await.unwrap().as_deref(), Some("same"));
}

/// The doors for the deployment's own rows refuse a catalog key, in Java's words.
async fn internal_doors_refuse_catalog_keys(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let settings = Settings::new(db.clone());
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    let refused = settings.set_internal(&mut tx, "sast_enabled", "true").await.unwrap_err();
    assert!(
        matches!(refused, SettingsError::CatalogKey(message) if message == "sast_enabled is a catalog setting, written through set(Setting, …).")
    );
    let refused = settings.replace_internal(&mut tx, "sast_enabled", "false", "true").await.unwrap_err();
    assert!(matches!(refused, SettingsError::CatalogKey(_)));
    let refused = settings.remove_internal(&mut tx, "sast_enabled").await.unwrap_err();
    assert!(
        matches!(refused, SettingsError::CatalogKey(message) if message == "sast_enabled is a catalog setting, and is not deleted.")
    );
    tx.rollback().await.unwrap();
}

/// Two instances storing the same key at once: exactly one is told it stored it, and both read back the winner.
async fn store_if_absent_lets_exactly_one_writer_win(engine: Engine) {
    let server = Migrated::start(engine).await;
    let mut contenders = Vec::new();
    for contender in 0..8 {
        let settings = Settings::new(server.connect().await);
        contenders.push(tokio::spawn(async move {
            let stored =
                settings.store_internal_if_absent("internal.signing_key", &format!("key-{contender}")).await.unwrap();
            (stored, settings.internal_value("internal.signing_key").await.unwrap().unwrap())
        }));
    }
    let mut outcomes = Vec::new();
    for contender in contenders {
        outcomes.push(contender.await.unwrap());
    }
    assert_eq!(outcomes.iter().filter(|(stored, _)| *stored).count(), 1, "one winner");
    let winner = outcomes.iter().find(|(stored, _)| *stored).unwrap().1.clone();
    assert!(outcomes.iter().all(|(_, read)| *read == winner), "everybody reads back the row that won");

    // A refusal with no row behind it is some other failure, and is returned, not swallowed.
    let db = server.connect().await;
    let settings = Settings::new(db.clone());
    let long_key = "k".repeat(300);
    assert!(settings.store_internal_if_absent(&long_key, "v").await.is_err(), "the key column refuses 300 characters");
}

/// Two transactions moving the same row from the value both read: the second waits on the first's lock, finds the
/// value moved, and is told so — the one told `true` is the one whose effect commits.
async fn replace_internal_arbitrates_between_two_transactions(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let settings = Settings::new(db.clone());
    assert!(settings.store_internal_if_absent("internal.token_state", "valid").await.unwrap());

    let mut first = db.begin(Mode::ReadWrite).await.unwrap();
    assert!(settings.replace_internal(&mut first, "internal.token_state", "valid", "expired").await.unwrap());
    let second = {
        let db = db.clone();
        let settings = settings.clone();
        tokio::spawn(async move {
            let mut second = db.begin(Mode::ReadWrite).await.unwrap();
            let moved =
                settings.replace_internal(&mut second, "internal.token_state", "valid", "expired").await.unwrap();
            second.commit().await.unwrap();
            moved
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(!second.is_finished(), "the second waits on the first's row lock");
    first.commit().await.unwrap();
    assert!(!second.await.unwrap(), "and then finds the value moved");
    assert_eq!(settings.internal_value("internal.token_state").await.unwrap().as_deref(), Some("expired"));

    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    settings.remove_internal(&mut tx, "internal.token_state").await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(settings.internal_value("internal.token_state").await.unwrap(), None);
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    assert!(
        !settings.replace_internal(&mut tx, "internal.token_state", "expired", "valid").await.unwrap(),
        "no row, no move"
    );
    tx.rollback().await.unwrap();
}

/// A row without a value: stored as empty, internal as absent.
async fn a_row_without_a_value(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let settings = Settings::new(db.clone());
    let quote = match engine {
        Engine::MySql => "`",
        Engine::PostgreSql => "\"",
    };
    server.sql_as_admin(&format!("insert into t_setting ({quote}key{quote}, value) values ('internal.empty', null)"));
    server.sql_as_admin(&format!("insert into t_setting ({quote}key{quote}, value) values ('ticket_labels', null)"));
    assert_eq!(settings.internal_value("internal.empty").await.unwrap(), None);
    assert_eq!(settings.stored().await.unwrap().get("internal.empty").map(String::as_str), Some(""));
    assert_eq!(
        settings.get(Setting::TicketLabels).await.unwrap(),
        "",
        "a stored null is the empty value, not the default"
    );
}

/// A fresh installation is written the safe visibility, as a row; a choice already made is never undone.
async fn first_install_defaults_fill_only_what_nobody_set(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let settings = Settings::new(db.clone());
    assert_eq!(settings.get(Setting::TargetVisibility).await.unwrap(), "everyone", "the compatible default");

    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    assert_eq!(settings.apply_first_install_defaults(&mut tx).await.unwrap(), vec![Setting::TargetVisibility]);
    tx.commit().await.unwrap();
    assert!(settings.is_stored(Setting::TargetVisibility).await.unwrap(), "a written row, not a second default");
    assert_eq!(settings.get(Setting::TargetVisibility).await.unwrap(), "assigned");

    // The operator chooses `everyone`; a restart that applies the defaults again leaves the choice alone.
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    settings.set(&mut tx, Setting::TargetVisibility, "everyone").await.unwrap();
    assert_eq!(settings.apply_first_install_defaults(&mut tx).await.unwrap(), Vec::<Setting>::new());
    tx.commit().await.unwrap();
    assert_eq!(settings.get(Setting::TargetVisibility).await.unwrap(), "everyone");
}

macro_rules! on_both_engines {
    ($($name:ident),* $(,)?) => {
        mod mysql {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { super::$name(super::Engine::MySql).await; })*
        }
        mod postgres {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { super::$name(super::Engine::PostgreSql).await; })*
        }
    };
}

on_both_engines!(
    reads_take_the_row_or_the_catalog_s_default,
    writing_a_value_twice_updates_the_row,
    internal_doors_refuse_catalog_keys,
    store_if_absent_lets_exactly_one_writer_win,
    replace_internal_arbitrates_between_two_transactions,
    a_row_without_a_value,
    first_install_defaults_fill_only_what_nobody_set,
);
