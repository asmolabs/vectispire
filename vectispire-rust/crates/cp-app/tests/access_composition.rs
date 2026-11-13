//! **`vectispire.sign-in.*` reaches the services it configures** — the composition the binary runs
//! (`access::compose`, called by `main` with the runtime's `Settings::sign_in`), exercised: the settings were read and
//! none of them reached a service, so the shipped ceilings held whatever an operator set, and no unit test of a service
//! could see it (`AGENTS.md`, "a wiring that is not exercised is not wired").
//!
//! From the environment, as the binary reads it: the ceilings the sign-in flows are built with, the bound every
//! password derivation of the process runs under, and the session cleanup purging the known clients at the retention
//! set — run on a real database, a client seven days and one second old purged where the shipped thirty days keep it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use vectispire_cp_access::derivations::{self, DerivationGate};
use vectispire_cp_access::login_throttle::SignInLimits;
use vectispire_cp_access::throttle::{SharedClock, SignInStore};
use vectispire_cp_db::Engine;
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_maintenance::Sequence;
use vectispire_cp_runtime::Settings;
use vectispire_cp_runtime::property::Environment;

fn settings(variables: &[(&str, &str)]) -> Settings {
    Settings::load(&Environment::of(variables.iter().copied(), [])).unwrap().0
}

#[tokio::test(flavor = "multi_thread")]
async fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    run(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn on_postgresql() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    run(Engine::PostgreSql).await;
}

async fn run(engine: Engine) {
    let set = settings(&[
        ("VECTISPIRE_SIGN_IN_FAILURES_PER_ACCOUNT_FROM_CLIENT", "3"),
        ("VECTISPIRE_SIGN_IN_FAILURES_PER_ACCOUNT", "40"),
        ("VECTISPIRE_SIGN_IN_FAILURES_PER_CLIENT", "0"),
        ("VECTISPIRE_SIGN_IN_KNOWN_CLIENT_RETENTION", "P7D"),
        ("VECTISPIRE_SIGN_IN_DERIVATIONS_CONCURRENT", "3"),
        ("VECTISPIRE_SIGN_IN_DERIVATIONS_QUEUE_WAIT", "PT0.25S"),
    ]);
    let server = TestDatabase::start(engine).await;
    let db = server.connect().await;
    let clock: SharedClock = Arc::new(vectispire_cp_access::credentials::SystemClock);
    let credentials = Arc::new(vectispire_cp_access::credentials::CredentialService::new(
        db.clone(),
        clock.clone(),
        vectispire_cp_access::credentials::SessionPolicy::default(),
        Arc::new(vectispire_cp_agents::AgentDirectoryImpl::new(db.clone())),
        vectispire_cp_access::credentials::ScimToken::default(),
    ));

    let access = vectispire_cp_app::access::compose(&set.sign_in, credentials, db.clone(), clock.clone());

    // The ceilings, a zero one being the shipped twenty, and the retention.
    assert_eq!(access.limits, SignInLimits::new(3, 40, 20, time::Duration::days(7)));
    // The bound, for every derivation of the process.
    let gate = derivations::gate();
    assert_eq!((gate.permits(), gate.wait()), (3, Duration::from_millis(250)));

    // The cleanup, run: past seven days a client is forgotten, within them it is kept.
    assert_eq!(access.session_cleanup.sequence(), Sequence::SessionCleanup);
    let store = vectispire_cp_access::SqlSignInStore::new(db.clone());
    let now = time::OffsetDateTime::now_utc();
    store
        .insert_known_client("past-the-retention", 1, now - time::Duration::days(7) - time::Duration::minutes(1))
        .await
        .unwrap();
    store.insert_known_client("within-it", 1, now - time::Duration::days(6)).await.unwrap();
    access.session_cleanup.run().await.unwrap();
    let since = now - time::Duration::days(365);
    assert!(!store.known_client_after("past-the-retention", since).await.unwrap(), "purged at the retention set");
    assert!(store.known_client_after("within-it", since).await.unwrap());

    // An environment that sets nothing composes the shipped values.
    let shipped = settings(&[]);
    assert_eq!(vectispire_cp_app::access::sign_in_limits(&shipped.sign_in), SignInLimits::default());
    let gate = vectispire_cp_app::access::derivation_gate(&shipped.sign_in);
    assert_eq!((gate.permits(), gate.wait()), (DerivationGate::default_permits(), Duration::from_secs(2)));
}
