//! The integrations' registry on real servers (decision 0040) — `IntegrationsTest`: V94's seed is the list the code
//! knows, a switch changes once and says so, a key without a row reads off, what is in use is not switched off, and a
//! configuration that holds an integration makes the governor's switch wait for it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use support::Migrated;
use time::OffsetDateTime;
use vectispire_cp_db::{Engine, Mode, Tx};
use vectispire_cp_settings::{InUse, InUseFuture, Integrations, IntegrationsError};
use vectispire_domain::integrations::{Integration, IntegrationFamily};
use vectispire_domain::siem::SiemProtocol;

fn at() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_793_000_000).unwrap()
}

/// What a module's configuration answers: in use for the integrations listed, with this sentence.
struct Using(Mutex<Vec<Integration>>);

impl InUse for Using {
    fn in_use<'a>(&'a self, _tx: &'a mut Tx, integration: Integration) -> InUseFuture<'a> {
        let used = self.0.lock().unwrap().contains(&integration);
        Box::pin(async move { Ok(used.then(|| "the export sends over it.".to_owned())) })
    }
}

fn registry(db: &vectispire_cp_db::Db, using: Arc<Using>) -> Integrations {
    Integrations::new(db.clone(), vec![using], Arc::new(at))
}

async fn the_seed_is_the_list_the_code_knows(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let integrations = registry(&db, Arc::new(Using(Mutex::new(Vec::new()))));
    let listed = integrations.list().await.unwrap();
    let keys: Vec<&str> = listed.iter().map(|view| view.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "forge.github",
            "forge.gitlab",
            "siem.webhook",
            "siem.syslog_udp",
            "siem.syslog_tcp",
            "siem.syslog_tls",
            "ai.ollama",
            "ai.openai",
            "notification.webhook",
            "notification.teams",
            "notification.slack",
            "notification.discord",
            "notification.mail",
            "tracker.gitlab",
            "tracker.github",
            "tracker.jira",
            "tracker.servicenow",
        ],
        "Integration.all()'s order"
    );
    // Seeded enabled, and nobody's gesture: no author, no date.
    assert!(listed.iter().all(|view| view.enabled && view.updated_at.is_none() && view.updated_by.is_none()));
    assert_eq!(
        (listed[5].family, listed[5].name),
        (IntegrationFamily::Siem.wire_name(), "syslog_tls"),
        "the family and the name as the API answers them"
    );
}

async fn a_switch_changes_once_and_the_same_state_writes_nothing(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let integrations = registry(&db, Arc::new(Using(Mutex::new(Vec::new()))));
    let discord = Integration::by_key("notification.discord").unwrap();

    let off = integrations.switch_to(discord, false, "governor").await.unwrap();
    assert!(off.changed);
    assert_eq!(
        (off.integration.enabled, off.integration.updated_at, off.integration.updated_by.as_deref()),
        (false, Some(at()), Some("governor"))
    );
    assert!(!integrations.is_enabled(discord).await.unwrap());
    assert!(matches!(integrations.require_enabled(discord).await, Err(IntegrationsError::Disabled(_))));

    let again = integrations.switch_to(discord, false, "another").await.unwrap();
    assert!(!again.changed, "the same state again changes nothing");
    assert_eq!(again.integration.updated_by.as_deref(), Some("governor"), "and writes nothing");

    assert!(integrations.switch_to(discord, true, "governor").await.unwrap().changed);
    assert!(integrations.is_enabled(discord).await.unwrap());
}

async fn a_key_without_a_row_reads_off_until_enabled(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    // An integration that arrived after V94: no row.
    server.sql_as_admin("delete from t_integration where integration_key = 'tracker.servicenow'");
    let integrations = registry(&db, Arc::new(Using(Mutex::new(Vec::new()))));
    let servicenow = Integration::by_key("tracker.servicenow").unwrap();
    assert!(!integrations.is_enabled(servicenow).await.unwrap());
    let view = integrations.list().await.unwrap().into_iter().find(|view| view.key == "tracker.servicenow").unwrap();
    assert!(!view.enabled);

    let off = integrations.switch_to(servicenow, false, "governor").await.unwrap();
    assert!(!off.changed, "switching off what is absent writes nothing");
    let on = integrations.switch_to(servicenow, true, "governor").await.unwrap();
    assert!(on.changed && on.integration.enabled);
    assert_eq!(on.integration.updated_by.as_deref(), Some("governor"));
}

async fn what_is_in_use_is_not_switched_off(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let tls = Integration::of_siem(SiemProtocol::SyslogTls);
    let using = Arc::new(Using(Mutex::new(vec![tls])));
    let integrations = registry(&db, using.clone());

    let refused = integrations.switch_to(tls, false, "governor").await.unwrap_err();
    assert_eq!(
        refused.to_string(),
        "The integration \"siem.syslog_tls\" is in use and cannot be disabled: the export sends over it."
    );
    assert!(matches!(refused, IntegrationsError::InUse(integration, _) if integration == tls));
    assert!(integrations.is_enabled(tls).await.unwrap(), "nothing changed");
    // Enabling is never refused for being in use, and another transport is not this one.
    assert!(!integrations.switch_to(tls, true, "governor").await.unwrap().changed);
    let udp = Integration::of_siem(SiemProtocol::SyslogUdp);
    assert!(integrations.switch_to(udp, false, "governor").await.unwrap().changed);

    using.0.lock().unwrap().clear();
    assert!(integrations.switch_to(tls, false, "governor").await.unwrap().changed);
}

/// The save holds the row `for share`; the switch, which takes it `for update`, waits for the save to commit.
async fn a_held_integration_makes_the_switch_wait(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let tls = Integration::of_siem(SiemProtocol::SyslogTls);
    let integrations = registry(&db, Arc::new(Using(Mutex::new(Vec::new()))));

    let mut save = db.begin(Mode::ReadWrite).await.unwrap();
    integrations.hold_enabled(&mut save, tls).await.unwrap();
    let switch = tokio::spawn({
        let integrations = integrations.clone();
        async move { integrations.switch_to(tls, false, "governor").await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!switch.is_finished(), "the switch waits for the save that holds the row");
    save.commit().await.unwrap();
    assert!(switch.await.unwrap().unwrap().changed);

    // Off, a hold is refused.
    let mut late = db.begin(Mode::ReadWrite).await.unwrap();
    assert!(matches!(integrations.hold_enabled(&mut late, tls).await, Err(IntegrationsError::Disabled(_))));
    late.rollback().await.unwrap();
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
    the_seed_is_the_list_the_code_knows,
    a_switch_changes_once_and_the_same_state_writes_nothing,
    a_key_without_a_row_reads_off_until_enabled,
    what_is_in_use_is_not_switched_off,
    a_held_integration_makes_the_switch_wait,
);
