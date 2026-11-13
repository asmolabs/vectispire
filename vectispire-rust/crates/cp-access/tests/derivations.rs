//! The bound on password derivations running at once — `DerivationGateTest`, and the places Java's `AuthService` and
//! `TotpService` meet a saturated bound: the sign-in, the password change and the MFA enrolment take their attempt back
//! and answer 503, never "wrong password".
//!
//! **One test, in a binary of its own**: the bound is the process's (`derivations::bound`), as Java's is
//! `PasswordHasher`'s, so a test that closes it would fail every other test deriving in the same process at that moment.
//! Each case below installs what it needs and puts the shipped bound back.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod sign_in_support;
mod support;

use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sign_in_support::{HandClock, NOW, PASSWORD, account, flow};
use vectispire_cp_access::credentials::{
    CredentialService, IssueError, IssuerSees, KeyRequest, ScimToken, SessionPolicy, StoreError, saturation,
};
use vectispire_cp_access::derivations::{self, DerivationGate, DerivationsSaturated};
use vectispire_cp_access::login_throttle::{account_key, account_key_from_client, user_key_from_client};
use vectispire_cp_access::passwords;
use vectispire_cp_access::second_factor::SecondFactorError;
use vectispire_cp_access::sign_in::{LoginRequest, SignInError};
use vectispire_cp_access::throttle::SharedClock;
use vectispire_cp_access::totp;
use vectispire_cp_db::{Db, Engine, ScanTarget};
use vectispire_cp_http::credentials::{BoxFuture, Credentials, KeyLookup};

/// Takes the gate's only permit on a thread of its own and holds it until the sender is dropped or sent to.
fn hold(gate: Arc<DerivationGate>) -> (mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (release, held) = mpsc::channel::<()>();
    let (taken, taking) = mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime
            .block_on(gate.run(|| {
                taken.send(()).unwrap();
                let _ = held.recv_timeout(Duration::from_secs(10));
            }))
            .unwrap();
    });
    taking.recv_timeout(Duration::from_secs(10)).unwrap();
    (release, holder)
}

/// `saturationIsRefused` and `aFailedDerivationGivesItsPermitBack`.
async fn past_the_bound_a_derivation_waits_its_turn_then_is_refused_saying_when_to_retry() {
    let gate = Arc::new(DerivationGate::new(1, Duration::from_millis(50)));
    let (release, holder) = hold(gate.clone());
    let started = Instant::now();
    let refused = gate.run(|| "second").await.unwrap_err();
    assert!(started.elapsed() >= Duration::from_millis(50), "it waited its turn first");
    assert_eq!(refused.retry_after(), Duration::from_secs(1), "the gate's wait, at least a second");
    release.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(gate.run(|| "after").await, Ok("after"));

    // A derivation that panics — a malformed parameter, an allocation refused — does not keep its permit.
    for _ in 0..3 {
        let failing = gate.clone();
        let outcome = tokio::spawn(async move { failing.run(|| panic!("derivation failed")).await }).await;
        assert!(outcome.is_err());
    }
    assert_eq!(gate.available(), 1);
    assert_eq!(gate.run(|| "next").await, Ok("next"));
}

/// `theHasherIsBounded`: every derivation of the module runs under the bound in force, and gets the shipped one back.
async fn the_hasher_is_bounded() {
    let hash = passwords::hash(PASSWORD);
    let closed = DerivationGate::new(1, Duration::from_millis(20));
    derivations::bound(closed);
    let (release, holder) = hold(derivations::gate());
    assert!(passwords::verify_bounded(Some(PASSWORD), Some(&hash)).await.is_err());
    assert!(passwords::hash_bounded("another").await.is_err());
    // A hash Argon2 would not derive asks for no permit: it is false, as Java's `verify` answers it before deriving.
    assert_eq!(passwords::verify_bounded(Some(PASSWORD), Some("$bcrypt$x")).await, Ok(false));
    release.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(passwords::verify_bounded(Some(PASSWORD), Some(&hash)).await, Ok(true));
    derivations::bound(DerivationGate::new(0, Duration::ZERO));
    assert_eq!(derivations::gate().permits(), DerivationGate::default_permits());
}

/// **Busy is not a failure.** Saturated, the sign-in takes back every row it counted — a person retrying through a busy
/// minute would otherwise lock themselves out — and goes up as `DerivationsSaturated`, for a known name and an unknown
/// one alike; the password change and the enrolment take their reservation back too.
async fn a_saturated_derivation_counts_nothing_and_says_nothing() {
    let clock: SharedClock = HandClock::at(NOW);
    let (flow, store, log, doors) = flow(clock);
    store.add(account(1, "alice", true));
    derivations::bound(DerivationGate::new(1, Duration::from_millis(20)));
    let (release, holder) = hold(derivations::gate());

    for name in ["alice", "nobody"] {
        let attempt =
            LoginRequest { username: name, password: PASSWORD, user_agent: None, ip_address: Some("10.0.0.7") };
        let refused = flow.sign_in(&attempt).await;
        assert!(matches!(refused, Err(SignInError::Saturated(_))), "{name}: {refused:?}");
        assert_eq!(store.attempts_under(&user_key_from_client(name, "10.0.0.7")), 0, "{name}: taken back");
    }
    assert_eq!(store.attempts_under(&account_key(1)), 0);
    assert!(doors.opened().is_empty());
    assert!(log.entries().is_empty(), "nothing happened that an entry could describe");

    let change =
        flow.change_password(1, None, Some(PASSWORD), Some("a new invented passphrase"), Some("10.0.0.7"), None);
    assert!(matches!(change.await, Err(vectispire_cp_access::accounts::AccountError::Saturated(_))));
    let secret = totp::generate_secret();
    let code = totp::generate_code(&secret, NOW).unwrap();
    let enrol = flow.second_factor().enable(1, PASSWORD, &secret, &code, Some("10.0.0.7"), None).await;
    assert!(matches!(enrol, Err(SecondFactorError::Saturated(_))), "{enrol:?}");
    assert_eq!(store.attempts_under(&account_key_from_client(1, "10.0.0.7")), 0, "both reservations taken back");
    assert_eq!(store.attempts_under(&account_key(1)), 0);
    assert!(!store.user(1).mfa_enabled);

    release.send(()).unwrap();
    holder.join().unwrap();
    derivations::bound(DerivationGate::new(0, Duration::ZERO));
}

/// No key is restricted to a target here.
struct SeesNothing;

impl IssuerSees for SeesNothing {
    fn issuer_sees<'a>(&'a self, _issuer: i64, _target: ScanTarget) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async { Ok(false) })
    }
}

async fn keys_stored(db: &Db) -> i64 {
    match db {
        Db::MySql(pool) => sqlx::query_scalar("select count(*) from t_api_key").fetch_one(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar("select count(*) from t_api_key").fetch_one(pool).await.unwrap(),
    }
}

/// **An API key is a password to the bound**: issuing one derives its hash under a permit, as `PasswordHasher.hash`
/// does for `ApiKeyAdministrationService.issue` and `AgentKeys.issue`, and presenting one verifies it under a permit.
/// Saturated, issuing stores nothing and goes up as the gate's refusal — which the routes answer 503 — and presenting a
/// valid key is "busy", which the chain answers 503, never "no credential".
async fn a_key_is_issued_and_verified_under_the_bound(engine: Engine) {
    let database = support::Migrated::start(engine).await;
    let db = &database.db;
    let credentials = CredentialService::new(
        db.clone(),
        support::HandClock::at(support::now()),
        SessionPolicy::default(),
        Arc::new(support::AgentsTable(db.clone())),
        ScimToken::default(),
    );
    let owner = support::account(db, "pipeline-owner", "SECURITY_CHAMPION", true, false).await;
    let issued = credentials
        .issue_integration_key(owner, &KeyRequest { name: Some("ci".into()), ..KeyRequest::default() }, &SeesNothing)
        .await
        .unwrap();
    let secret = issued.secret.expose().to_owned();

    derivations::bound(DerivationGate::new(1, Duration::from_millis(20)));
    let (release, holder) = hold(derivations::gate());
    let refused = credentials
        .issue_integration_key(owner, &KeyRequest { name: Some("cd".into()), ..KeyRequest::default() }, &SeesNothing)
        .await;
    match refused {
        Err(IssueError::Store(failure)) => {
            assert_eq!(saturation(&failure).map(DerivationsSaturated::retry_after_seconds), Some(1));
        }
        other => panic!("the integration key was not refused as saturated: {other:?}"),
    }
    let agent_key = credentials.issue_agent_key("agent-builder").await.map(|(id, _)| id);
    assert!(agent_key.as_ref().is_err_and(|failure| saturation(failure).is_some()), "{agent_key:?}");
    assert_eq!(keys_stored(db).await, 1, "nothing stored past the bound");
    match credentials.api_key_lookup(&secret).await {
        KeyLookup::Busy { retry_after_seconds, .. } => assert_eq!(retry_after_seconds, 1),
        _ => panic!("a valid key the gate could not verify is busy, not absent"),
    }

    release.send(()).unwrap();
    holder.join().unwrap();
    derivations::bound(DerivationGate::new(0, Duration::ZERO));
    assert!(matches!(credentials.api_key_lookup(&secret).await, KeyLookup::Found(_)));
}

/// `ApiExceptionHandler.derivationsSaturated`: 503, the sentence, `code` then `retryAfterSeconds`, and `Retry-After`.
fn the_refusal_is_answered_as_java_answers_it(refused: DerivationsSaturated) {
    let problem = refused.problem();
    assert_eq!(problem.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        problem.body(),
        "{\"detail\":\"Too many passwords are being verified at once. Try again in a few seconds.\",\"status\":503,\
         \"title\":\"Service Unavailable\",\"code\":\"unavailable\",\"retryAfterSeconds\":2}"
    );
    let response = axum::response::IntoResponse::into_response(problem);
    assert_eq!(response.headers().get("Retry-After").unwrap(), "2");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bound_on_derivations() {
    past_the_bound_a_derivation_waits_its_turn_then_is_refused_saying_when_to_retry().await;
    the_hasher_is_bounded().await;
    a_saturated_derivation_counts_nothing_and_says_nothing().await;
    if vectispire_cp_db::testing::runs_on(Engine::MySql) {
        a_key_is_issued_and_verified_under_the_bound(Engine::MySql).await;
    }

    let gate = Arc::new(DerivationGate::new(1, Duration::from_secs(2)));
    let (release, holder) = hold(gate.clone());
    let refused = gate.run(|| ()).await.unwrap_err();
    release.send(()).unwrap();
    holder.join().unwrap();
    the_refusal_is_answered_as_java_answers_it(refused);
}
