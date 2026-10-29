//! The sign-in on MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`: every statement of `SqlSignInStore`,
//! then what only a database shows — `AuthDatabaseTest`, `TotpServiceTest`, `MfaChallengeIsSharedTest`,
//! `AuthenticationCeilingsTest` and `RateWindowsIntegrationTest` — the concurrency properties among them: a burst
//! against a ceiling of five admits at most five, a challenge's count loses no presentation, a replayed step and a
//! backup code spent twice are refused by the statement, and a window's first-hit race counts both hits.
//!
//! **Docker is required, and its absence fails the test.**

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "accounts_support/mod.rs"]
mod accounts_support;
mod sign_in_support;
mod support;

use std::sync::Arc;

use accounts_support::RawCredentials;
use sign_in_support::{Log, PASSWORD};
use support::{Bind, HandClock, Migrated, execute};
use time::{Duration, OffsetDateTime};
use vectispire_cp_access::SqlAccountStore;
use vectispire_cp_access::SqlSignInStore;
use vectispire_cp_access::accounts::{PasswordChange, StoreError};
use vectispire_cp_access::credentials::{CredentialService, ScimToken, SessionPolicy, hash_of};
use vectispire_cp_access::login_throttle::{MAX_ATTEMPTS_PER_USER, MAX_SECOND_FACTOR_FAILURES};
use vectispire_cp_access::passwords;
use vectispire_cp_access::rate_windows::{Limit, RateWindowStore, RateWindows};
use vectispire_cp_access::second_factor::{Enrolled, SecondFactorError, backup_context, secret_context};
use vectispire_cp_access::session_cleanup::session_cleanup_task;
use vectispire_cp_access::sign_in::{
    Challenge, LoginOutcome, LoginRequest, SignIn, SignInFlow, SignInMethodPolicy, SignInParts, Verification,
};
use vectispire_cp_access::throttle::{SharedClock, SignInStore, Throttle};
use vectispire_cp_access::totp;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, SecretState, VaultDoor};
use vectispire_cp_db::{Db, Engine};
use vectispire_domain::secret::Secret;

/// The throwaway control plane's key — base64 of an invented 32-byte label.
const KEY: &str = "dnMtcnMtcDFjLWVuY3J5cHRpb24ta2V5LWludmVudCE="; // gitleaks:allow — invented

type Users = SqlAccountStore<RawCredentials>;
type Flow = SignInFlow<Users, Log, SqlSignInStore, Arc<CredentialService>, Arc<Encryption>>;

fn encryption() -> Arc<Encryption> {
    let door = VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(
        Encryption::new(&EncryptionConfig { key: Some(Secret::new(KEY)), ..EncryptionConfig::default() }, door)
            .unwrap(),
    )
}

fn credentials(db: &Db, clock: SharedClock) -> Arc<CredentialService> {
    Arc::new(CredentialService::new(
        db.clone(),
        clock,
        SessionPolicy::default(),
        Arc::new(support::AgentsTable(db.clone())),
        ScimToken::default(),
    ))
}

fn flow(db: &Db, clock: SharedClock, log: &Log) -> Flow {
    SignInFlow::new(SignInParts {
        users: SqlAccountStore::new(db.clone(), RawCredentials),
        audit: log.clone(),
        store: SqlSignInStore::new(db.clone()),
        sessions: credentials(db, clock.clone()),
        seal: encryption(),
        clock,
        methods: SignInMethodPolicy::new(false, true),
        provider_label: None,
    })
}

/// An account with a password, as the accounts module writes one; answers its id.
async fn account(db: &Db, username: &str, mfa: bool) -> i64 {
    let id = support::account(db, username, "USER", true, false).await;
    execute(
        db,
        "update t_user set password = ?, mfa_enabled = ? where id = ?",
        "update t_user set password = $1, mfa_enabled = $2 where id = $3",
        &[Bind::Text(&passwords::hash(PASSWORD)), Bind::Bool(mfa), Bind::Int(id)],
    )
    .await;
    id
}

fn now() -> OffsetDateTime {
    support::now()
}

fn request(username: &str) -> LoginRequest<'_> {
    LoginRequest { username, password: PASSWORD, user_agent: Some("curl/8"), ip_address: Some("10.0.0.1") }
}

async fn text(db: &Db, mysql: &str, postgres: &str) -> Vec<String> {
    match db {
        Db::MySql(pool) => sqlx::query_scalar(sqlx::AssertSqlSafe(mysql.to_owned())).fetch_all(pool).await.unwrap(),
        Db::PostgreSql(pool) => {
            sqlx::query_scalar(sqlx::AssertSqlSafe(postgres.to_owned())).fetch_all(pool).await.unwrap()
        }
    }
}

async fn rows(db: &Db, table: &str) -> i64 {
    let sql = format!("select count(*) from {table}");
    match db {
        Db::MySql(pool) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_one(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_one(pool).await.unwrap(),
    }
}

// ── every statement ──────────────────────────────────────────────────────────────────────────────────────────

async fn statements(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let store = SqlSignInStore::new(db.clone());
    let at = now();

    // t_login_attempt: written as Hibernate writes it, counted strictly after, deleted by ids, key and age.
    let ids = store.record_attempts(&["a".into(), "a".into(), "b".into()], at).await.unwrap();
    assert_eq!(ids.len(), 3);
    let stored =
        text(db, "select id from t_login_attempt order by id", "select id from t_login_attempt order by id").await;
    let mut expected: Vec<String> = ids.iter().map(|id| id.as_hyphenated().to_string()).collect();
    expected.sort();
    assert_eq!(stored, expected, "the UUID's text, lower case with hyphens");
    let found = store.attempts_after("a", at - Duration::microseconds(1)).await.unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|row| row.occurred_at == at), "{found:?}");
    assert!(store.attempts_after("a", at).await.unwrap().is_empty(), "strictly after");
    assert_eq!(store.delete_attempts(&ids[..2]).await.unwrap(), 2, "two ids, one statement");
    assert_eq!(store.delete_attempts(&[]).await.unwrap(), 0);
    store.record_attempts(&["b".into()], at - Duration::minutes(31)).await.unwrap();
    assert_eq!(store.delete_attempts_before(at - Duration::minutes(31)).await.unwrap(), 0, "strictly before");
    assert_eq!(store.delete_attempts_before(at - Duration::minutes(30)).await.unwrap(), 1);
    assert_eq!(store.delete_attempts_by_key("b").await.unwrap(), 1);
    assert_eq!(rows(db, "t_login_attempt").await, 0);

    // t_mfa_challenge.
    let alice = account(db, "alice", true).await;
    let challenge = Challenge {
        token_hash: hash_of("token"),
        user_id: alice,
        expires_at: at + Duration::minutes(5),
        attempts: 0,
        user_agent: Some("curl/8".into()),
        ip_address: Some("10.0.0.1".into()),
    };
    store.insert_challenge(&challenge).await.unwrap();
    assert_eq!(store.find_challenge(&challenge.token_hash).await.unwrap().as_ref(), Some(&challenge));
    assert_eq!(store.count_challenge_attempt(&challenge.token_hash).await.unwrap(), 1);
    assert_eq!(store.count_challenge_attempt("unknown").await.unwrap(), 0);
    assert_eq!(store.find_challenge(&challenge.token_hash).await.unwrap().unwrap().attempts, 1);
    assert_eq!(store.count_live_challenges(at + Duration::minutes(5)).await.unwrap(), 0, "live strictly after");
    assert_eq!(store.count_live_challenges(at).await.unwrap(), 1);
    assert_eq!(store.delete_expired_challenges(at + Duration::minutes(5)).await.unwrap(), 0, "expired strictly before");
    assert_eq!(store.discard_challenge(&challenge.token_hash).await.unwrap(), 1);
    assert_eq!(store.discard_challenge(&challenge.token_hash).await.unwrap(), 0);
    store.insert_challenge(&challenge).await.unwrap();
    assert_eq!(store.delete_expired_challenges(at + Duration::minutes(6)).await.unwrap(), 1);

    // t_user's second factor.
    assert_eq!(store.advance_totp_step(alice, 10).await.unwrap(), 1, "from null");
    assert_eq!(store.advance_totp_step(alice, 10).await.unwrap(), 0, "the same step");
    assert_eq!(store.advance_totp_step(alice, 9).await.unwrap(), 0, "an older one");
    assert_eq!(store.advance_totp_step(alice, 11).await.unwrap(), 1);
    // A role changed behind the enrolment's back stays changed: only the factor's columns are written.
    execute(
        db,
        "update t_user set role = 'ADMIN' where id = ?",
        "update t_user set role = 'ADMIN' where id = $1",
        &[Bind::Int(alice)],
    )
    .await;
    let later = at + Duration::seconds(1);
    store
        .enable_second_factor(
            alice,
            &Enrolled { totp_secret: "s".into(), backup_codes: "c1".into(), last_step: 7, at: later },
        )
        .await
        .unwrap();
    let factor_columns = format!(
        "select concat(role, '|', mfa_enabled, '|', coalesce(totp_secret, 'null'), '|', \
         coalesce(mfa_backup_codes, 'null'), '|', coalesce(totp_last_step, -1)) from t_user where id = {alice}"
    );
    let row = text(db, &factor_columns, &factor_columns).await;
    let enabled = if engine == Engine::MySql { "1" } else { "t" };
    assert_eq!(row, vec![format!("ADMIN|{enabled}|s|c1|7")]);
    assert_eq!(store.replace_backup_codes(alice, "c0", "c2", later).await.unwrap(), 0, "not the codes read");
    assert_eq!(store.replace_backup_codes(alice, "c1", "c2", later).await.unwrap(), 1);
    assert_eq!(store.replace_backup_codes(alice, "c1", "c3", later).await.unwrap(), 0, "spent by the first");
    let bob = account(db, "bob", false).await;
    let _carol = support::account(db, "carol", "USER", true, false).await; // no password
    assert_eq!(store.count_active_with_password().await.unwrap(), 2);
    assert_eq!(store.count_active_with_password_and_no_second_factor().await.unwrap(), 1);
    store.disable_second_factor(alice, later).await.unwrap();
    let row = text(db, &factor_columns, &factor_columns).await;
    let disabled = if engine == Engine::MySql { "0" } else { "f" };
    assert_eq!(row, vec![format!("ADMIN|{disabled}|null|null|-1")]);
    assert_eq!(store.count_active_with_password_and_no_second_factor().await.unwrap(), 2);
    let _ = bob;

    // t_rate_window.
    assert_eq!(store.increment("w").await.unwrap(), 0, "no row yet");
    store.insert_first("w", at + Duration::minutes(1)).await.unwrap();
    assert!(store.insert_first("w", at + Duration::minutes(1)).await.is_err(), "the primary key refuses a second");
    // On PostgreSQL the refused insert poisoned nothing: the increment that follows commits.
    assert_eq!(store.increment("w").await.unwrap(), 1);
    assert_eq!(store.hits_of("w").await.unwrap(), Some(2));
    assert_eq!(store.hits_of("none").await.unwrap(), None);
    store.insert_first("other:1", at - Duration::seconds(1)).await.unwrap();
    assert_eq!(store.delete_expired(at + Duration::minutes(1)).await.unwrap(), 1, "closed strictly before");
    assert_eq!(store.delete_by_key_prefix("w%").await.unwrap(), 1);
    assert_eq!(rows(db, "t_rate_window").await, 0);
}

#[tokio::test]
async fn every_statement_on_mysql() {
    statements(Engine::MySql).await;
}

#[tokio::test]
async fn every_statement_on_postgresql() {
    statements(Engine::PostgreSql).await;
}

// ── AuthDatabaseTest ─────────────────────────────────────────────────────────────────────────────────────────

async fn logging_in(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let clock: SharedClock = HandClock::at(now());
    let log = Log::default();
    let flow = flow(db, clock.clone(), &log);
    let alice = account(db, "alice", false).await;

    // A stale hash is rewritten on the way in, and still the same password.
    execute(
        db,
        "update t_user set password = ? where id = ?",
        "update t_user set password = $1 where id = $2",
        &[Bind::Text(&passwords::hash_with(PASSWORD, 4096, 1, 1).unwrap()), Bind::Int(alice)],
    )
    .await;
    let LoginOutcome::Success { issued, .. } = flow.login(&request("alice")).await.unwrap().outcome else { panic!() };
    let stored = text(db, "select password from t_user", "select password from t_user").await;
    assert!(!passwords::needs_rehash(stored.first().map(String::as_str)));
    assert!(passwords::verify(Some(PASSWORD), stored.first().map(String::as_str)));

    // The session is written, resolves back, and the store holds its hash, never the token.
    assert_eq!(issued.session.expires_at, clock.now() + SessionPolicy::default().absolute_lifetime);
    let sessions = credentials(db, clock.clone());
    assert!(sessions.resolve_session(issued.token.expose()).await.unwrap().is_some());
    assert_eq!(
        text(db, "select token_hash from t_session", "select token_hash from t_session").await,
        vec![hash_of(issued.token.expose())]
    );

    // The throttle counts real rows and locks after five: three rows per failure, none for the refusal.
    for _ in 0..MAX_ATTEMPTS_PER_USER {
        let wrong = LoginRequest { password: "wrong", ..request("alice") };
        assert!(matches!(flow.login(&wrong).await.unwrap().outcome, LoginOutcome::Invalid));
    }
    assert_eq!(rows(db, "t_login_attempt").await, 15);
    assert!(matches!(flow.login(&request("alice")).await.unwrap().outcome, LoginOutcome::Blocked(_)));
    assert_eq!(rows(db, "t_login_attempt").await, 15);

    // A success clears the account's and the name's counters and keeps the address's failures.
    execute(db, "delete from t_login_attempt", "delete from t_login_attempt", &[]).await;
    for _ in 0..2 {
        let wrong = LoginRequest { password: "wrong", ..request("alice") };
        flow.login(&wrong).await.unwrap();
    }
    assert!(matches!(flow.login(&request("alice")).await.unwrap().outcome, LoginOutcome::Success { .. }));
    let keys = text(db, "select counter_key from t_login_attempt", "select counter_key from t_login_attempt").await;
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert!(keys.iter().all(|key| key.starts_with("login:client:")), "{keys:?}");

    // A deactivated account is refused like any other.
    execute(
        db,
        "update t_user set is_active = false where id = ?",
        "update t_user set is_active = false where id = $1",
        &[Bind::Int(alice)],
    )
    .await;
    assert!(matches!(flow.login(&request("alice")).await.unwrap().outcome, LoginOutcome::Invalid));
}

#[tokio::test]
async fn logging_in_on_mysql() {
    logging_in(Engine::MySql).await;
}

#[tokio::test]
async fn logging_in_on_postgresql() {
    logging_in(Engine::PostgreSql).await;
}

// ── TotpServiceTest, with the real encryption ────────────────────────────────────────────────────────────────

async fn second_factor(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let clock: SharedClock = HandClock::at(now());
    let flow = flow(db, clock.clone(), &Log::default());
    let factor = flow.second_factor();
    let users = SqlAccountStore::new(db.clone(), RawCredentials);
    use vectispire_cp_access::accounts::AccountStore;

    let before = factor.enrolment().await.unwrap();
    let id = account(db, "dana", false).await;
    let at = clock.now();
    let secret = factor.setup("dana").secret;
    let codes = factor.enable(id, secret.expose(), &totp::generate_code(secret.expose(), at).unwrap()).await.unwrap();
    let after = factor.enrolment().await.unwrap();
    assert_eq!(
        (after.password_accounts - before.password_accounts, after.without_second_factor),
        (1, before.without_second_factor)
    );

    // Sealed under Java's contexts, so the Java control plane reads them: opened here with the same key and context.
    let user = users.find_by_id(id).await.unwrap().unwrap();
    let sealed =
        encryption().inspect(user.totp_secret.as_ref().unwrap().expose(), &format!("user:totp_secret:{id}")).await;
    assert_eq!((sealed.state(), sealed.plain_text()), (SecretState::Current, secret.expose()));
    let sealed = encryption()
        .inspect(user.mfa_backup_codes.as_ref().unwrap().expose(), &format!("user:backup_codes:{id}"))
        .await;
    let joined = codes.iter().map(|code| code.expose()).collect::<Vec<_>>().join(",");
    assert_eq!((sealed.state(), sealed.plain_text()), (SecretState::Current, joined.as_str()));
    assert_eq!(secret_context(id), format!("user:totp_secret:{id}"));
    assert_eq!(backup_context(id), format!("user:backup_codes:{id}"));

    // The enrolment's code is spent; the next opens once.
    assert!(!factor.verify(&user, totp::generate_code(secret.expose(), at).as_deref()).await.unwrap());
    let next = totp::generate_code(secret.expose(), at + Duration::seconds(30)).unwrap();
    assert!(factor.verify(&user, Some(&next)).await.unwrap());
    let reread = users.find_by_id(id).await.unwrap().unwrap();
    assert!(!factor.verify(&reread, Some(&next)).await.unwrap(), "a replay");

    // A backup code spent through one copy of the account is refused through another; the others remain.
    let (first, second) = (users.find_by_id(id).await.unwrap().unwrap(), users.find_by_id(id).await.unwrap().unwrap());
    assert!(factor.verify(&first, Some(codes[0].expose())).await.unwrap());
    assert!(!factor.verify(&second, Some(codes[0].expose())).await.unwrap());
    assert!(factor.verify(&users.find_by_id(id).await.unwrap().unwrap(), Some(codes[1].expose())).await.unwrap());

    // Enrolling over an active factor is refused, and the factor still opens.
    let attacker = totp::generate_secret();
    let refused = factor.enable(id, &attacker, &totp::generate_code(&attacker, at).unwrap()).await;
    assert!(matches!(refused, Err(SecondFactorError::InvalidInput(message)) if message.contains("already enabled")));
    assert!(factor.verify(&users.find_by_id(id).await.unwrap().unwrap(), Some(codes[2].expose())).await.unwrap());

    // Disabled with a backup code: the four columns null.
    factor.disable(id, codes[3].expose()).await.unwrap();
    let off = users.find_by_id(id).await.unwrap().unwrap();
    assert!(
        !off.mfa_enabled && off.totp_secret.is_none() && off.mfa_backup_codes.is_none() && off.totp_last_step.is_none()
    );
}

#[tokio::test]
async fn the_second_factor_on_mysql() {
    second_factor(Engine::MySql).await;
}

#[tokio::test]
async fn the_second_factor_on_postgresql() {
    second_factor(Engine::PostgreSql).await;
}

// ── MfaChallengeIsSharedTest ─────────────────────────────────────────────────────────────────────────────────

async fn challenge_shared(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let clock: SharedClock = HandClock::at(now());
    let (one, other) = (flow(db, clock.clone(), &Log::default()), flow(db, clock.clone(), &Log::default()));
    account(db, "erin", true).await;
    let store = SqlSignInStore::new(db.clone());

    let SignIn::ChallengeIssued(token) = one.sign_in(&request("erin")).await.unwrap() else { panic!() };
    assert!(store.find_challenge(token.expose()).await.unwrap().is_none(), "the token itself is no key");
    let stored = store.find_challenge(&hash_of(token.expose())).await.unwrap().expect("persisted");
    assert_eq!(stored.attempts, 0);
    assert!(stored.expires_at > clock.now());

    // The other instance recognises it: refused as a wrong code, not as an expired challenge — the account has no
    // secret, so no code is right.
    for _ in 0..3 {
        assert!(matches!(other.verify(token.expose(), "000000", None, None).await.unwrap(), Verification::WrongCode));
    }
    assert!(store.find_challenge(&hash_of(token.expose())).await.unwrap().is_none(), "gone for every instance");
}

#[tokio::test]
async fn a_challenge_is_shared_on_mysql() {
    challenge_shared(Engine::MySql).await;
}

#[tokio::test]
async fn a_challenge_is_shared_on_postgresql() {
    challenge_shared(Engine::PostgreSql).await;
}

/// A User-Agent past `varchar(255)` is clipped on a character boundary and the challenge issued — the Java defect
/// fixed in asmolabs/vectispire#84: stored as sent, the insert failed after the password was accepted.
async fn long_user_agent(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let flow = flow(db, HandClock::at(now()), &Log::default());
    account(db, "fred", true).await;
    // 254 letters, then a surrogate pair at the cut: Java's `BoundedText.clip` leaves the pair out whole.
    let agent = format!("{}\u{1F600}{}", "a".repeat(254), "b".repeat(100));
    let attempt = LoginRequest { user_agent: Some(&agent), ..request("fred") };
    let SignIn::ChallengeIssued(token) = flow.sign_in(&attempt).await.unwrap() else {
        panic!("a long User-Agent still gets its challenge");
    };
    let stored =
        SqlSignInStore::new(db.clone()).find_challenge(&hash_of(token.expose())).await.unwrap().expect("persisted");
    assert_eq!(stored.user_agent.as_deref(), Some("a".repeat(254).as_str()));
}

#[tokio::test]
async fn a_user_agent_past_the_column_is_clipped_on_mysql() {
    long_user_agent(Engine::MySql).await;
}

#[tokio::test]
async fn a_user_agent_past_the_column_is_clipped_on_postgresql() {
    long_user_agent(Engine::PostgreSql).await;
}

// ── AuthenticationCeilingsTest, and the statements raced ─────────────────────────────────────────────────────

const BURST: usize = 12;

async fn ceilings(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let clock: SharedClock = HandClock::at(now());
    let flow = Arc::new(flow(db, clock.clone(), &Log::default()));

    // A burst of reservations against one ceiling of five admits at most five, and keeps exactly their rows.
    let throttle = Arc::new(Throttle::new(SqlSignInStore::new(db.clone()), clock.clone()));
    let mut tasks = Vec::new();
    for _ in 0..BURST {
        let throttle = throttle.clone();
        tasks.push(tokio::spawn(async move { throttle.reserve(&[("burst".into(), 5)]).await.unwrap().admitted() }));
    }
    let mut admitted = 0;
    for task in tasks {
        admitted += usize::from(task.await.unwrap());
    }
    assert!(admitted <= 5, "{admitted} admitted past a ceiling of five");
    assert_eq!(rows(db, "t_login_attempt").await, i64::try_from(admitted).unwrap(), "refused rows taken back");

    // A burst of wrong passwords reaches the verification at most five times.
    let name = "burst";
    account(db, name, false).await;
    let mut tasks = Vec::new();
    for index in 0..BURST {
        let flow = flow.clone();
        tasks.push(tokio::spawn(async move {
            let (password, address) = (format!("wrong-{index}"), format!("198.51.100.{index}"));
            let attempt =
                LoginRequest { username: name, password: &password, user_agent: None, ip_address: Some(&address) };
            flow.login(&attempt).await.unwrap().outcome
        }));
    }
    let mut invalid = 0;
    for task in tasks {
        match task.await.unwrap() {
            LoginOutcome::Invalid => invalid += 1,
            LoginOutcome::Blocked(_) => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(invalid <= MAX_ATTEMPTS_PER_USER, "{invalid} wrong passwords verified");

    // A burst of wrong current passwords on a session is checked at most five times.
    let changer = account(db, "changer", false).await;
    let mut tasks = Vec::new();
    for index in 0..BURST {
        let flow = flow.clone();
        tasks.push(tokio::spawn(async move {
            let wrong = format!("wrong-{index}");
            flow.change_password(changer, None, Some(&wrong), Some("a new password of some length"), None, None)
                .await
                .unwrap()
        }));
    }
    let mut wrong = 0;
    for task in tasks {
        match task.await.unwrap() {
            PasswordChange::CurrentPasswordWrong => wrong += 1,
            PasswordChange::Throttled { .. } => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(wrong <= MAX_ATTEMPTS_PER_USER, "{wrong} wrong current passwords checked");

    // A burst of wrong codes across four challenges reaches the code check at most five times: the challenge's own
    // limit admits all twelve, so only the account's budget can stop them. The account has no secret: every code is
    // wrong, which is all a ceiling on wrong codes needs.
    account(db, "coder", true).await;
    let mut challenges = Vec::new();
    for _ in 0..4 {
        let SignIn::ChallengeIssued(token) = flow.sign_in(&request("coder")).await.unwrap() else { panic!() };
        challenges.push(token.expose().to_owned());
    }
    let mut tasks = Vec::new();
    for index in 0..BURST {
        let (flow, token) = (flow.clone(), challenges[index % 4].clone());
        tasks.push(tokio::spawn(async move {
            flow.verify(&token, &format!("00000{}", index % 10), None, None).await.unwrap()
        }));
    }
    let mut wrong_codes = 0;
    for task in tasks {
        match task.await.unwrap() {
            Verification::WrongCode => wrong_codes += 1,
            Verification::Throttled(_) | Verification::ChallengeInvalid => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(wrong_codes <= MAX_SECOND_FACTOR_FAILURES, "{wrong_codes} wrong codes checked");

    // A burst of wrong codes to switch the factor off reaches the code check at most five times.
    let disabler = account(db, "disabler", true).await;
    let mut tasks = Vec::new();
    for index in 0..BURST {
        let flow = flow.clone();
        tasks.push(tokio::spawn(async move {
            match flow.second_factor().disable(disabler, &format!("00000{}", index % 10)).await {
                Ok(()) => "disabled",
                Err(SecondFactorError::Locked { .. }) => "locked",
                Err(SecondFactorError::InvalidInput(_)) => "wrong",
                Err(other) => panic!("{other:?}"),
            }
        }));
    }
    let mut outcomes = Vec::new();
    for task in tasks {
        outcomes.push(task.await.unwrap());
    }
    assert!(outcomes.iter().filter(|o| **o == "wrong").count() <= MAX_SECOND_FACTOR_FAILURES, "{outcomes:?}");
    assert!(!outcomes.contains(&"disabled"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_ceilings_hold_under_bursts_on_mysql() {
    ceilings(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_ceilings_hold_under_bursts_on_postgresql() {
    ceilings(Engine::PostgreSql).await;
}

async fn raced_statements(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let store = SqlSignInStore::new(db.clone());
    let id = account(db, "racer", true).await;

    // Sixteen presentations at once are sixteen counted.
    let challenge = Challenge {
        token_hash: hash_of("raced"),
        user_id: id,
        expires_at: now() + Duration::minutes(5),
        attempts: 0,
        user_agent: None,
        ip_address: None,
    };
    store.insert_challenge(&challenge).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move { store.count_challenge_attempt(&hash_of("raced")).await.unwrap() }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 1);
    }
    assert_eq!(store.find_challenge(&hash_of("raced")).await.unwrap().unwrap().attempts, 16);

    // One step, two presentations at once: one wins.
    let (a, b) = (store.clone(), store.clone());
    let (first, second) = tokio::join!(
        tokio::spawn(async move { a.advance_totp_step(id, 99).await.unwrap() }),
        tokio::spawn(async move { b.advance_totp_step(id, 99).await.unwrap() })
    );
    assert_eq!(first.unwrap() + second.unwrap(), 1, "a replayed step is refused by the statement");

    // One backup code, two spends at once: one wins.
    execute(
        db,
        "update t_user set mfa_backup_codes = 'v1' where id = ?",
        "update t_user set mfa_backup_codes = 'v1' where id = $1",
        &[Bind::Int(id)],
    )
    .await;
    let (a, b) = (store.clone(), store.clone());
    let at = now();
    let (first, second) = tokio::join!(
        tokio::spawn(async move { a.replace_backup_codes(id, "v1", "v2-a", at).await.unwrap() }),
        tokio::spawn(async move { b.replace_backup_codes(id, "v1", "v2-b", at).await.unwrap() })
    );
    assert_eq!(first.unwrap() + second.unwrap(), 1, "one of two racing spends wins");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn raced_statements_on_mysql() {
    raced_statements(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn raced_statements_on_postgresql() {
    raced_statements(Engine::PostgreSql).await;
}

// ── RateWindowsIntegrationTest ───────────────────────────────────────────────────────────────────────────────

/// The real store, with another instance's insert forced between this one's increment (which found no row) and its
/// insert (which the key then refuses).
#[derive(Clone, Debug)]
struct Racing {
    real: SqlSignInStore,
    expires: OffsetDateTime,
    interleaved: Arc<std::sync::atomic::AtomicBool>,
}

impl RateWindowStore for Racing {
    async fn increment(&self, key: &str) -> Result<u64, StoreError> {
        let result = self.real.increment(key).await?;
        if !self.interleaved.swap(true, std::sync::atomic::Ordering::SeqCst) {
            assert_eq!(result, 0, "nobody had hit this window yet");
            self.real.insert_first(key, self.expires).await?;
        }
        Ok(result)
    }

    async fn insert_first(&self, key: &str, expires_at: OffsetDateTime) -> Result<(), StoreError> {
        self.real.insert_first(key, expires_at).await
    }

    async fn hits_of(&self, key: &str) -> Result<Option<i32>, StoreError> {
        self.real.hits_of(key).await
    }

    async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        self.real.delete_expired(now).await
    }

    async fn delete_by_key_prefix(&self, pattern: &str) -> Result<u64, StoreError> {
        self.real.delete_by_key_prefix(pattern).await
    }
}

const MINUTE: std::time::Duration = std::time::Duration::from_secs(60);

fn key_of(at: OffsetDateTime, subject: &str) -> String {
    use sha2::{Digest, Sha256};
    let number = (at.unix_timestamp_nanos() / 1_000_000).div_euclid(60_000);
    let hex: String = Sha256::digest(subject.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect();
    format!("webhook:{number}:{hex}")
}

async fn rate_windows(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let at = now();
    let clock: SharedClock = HandClock::at(at);
    let store = SqlSignInStore::new(db.clone());
    let windows = RateWindows::new(store.clone(), clock.clone());

    // Exactly the ceiling, one after another, every hit counted.
    let mut admitted = Vec::new();
    for _ in 0..7 {
        admitted.push(windows.hit(Limit::TicketWebhook, Some("203.0.113.1"), 5, MINUTE).await.admitted);
    }
    assert_eq!(admitted, [true, true, true, true, true, false, false]);
    assert_eq!(store.hits_of(&key_of(at, "203.0.113.1")).await.unwrap(), Some(7));

    // A first hit that loses its insert to another instance is counted, not lost.
    let interleaved = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let racing = Racing { real: store.clone(), expires: at + Duration::minutes(1), interleaved: interleaved.clone() };
    let outcome =
        RateWindows::new(racing, clock.clone()).hit(Limit::TicketWebhook, Some("203.0.113.2"), 5, MINUTE).await;
    assert!(interleaved.load(std::sync::atomic::Ordering::SeqCst));
    assert!(outcome.admitted);
    assert_eq!(
        store.hits_of(&key_of(at, "203.0.113.2")).await.unwrap(),
        Some(2),
        "the other instance's hit and this one"
    );

    // Sixteen at once: no hit lost, none admitted past the ceiling.
    let windows = Arc::new(windows);
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let windows = windows.clone();
        tasks.push(tokio::spawn(async move {
            windows.hit(Limit::TicketWebhook, Some("203.0.113.3"), 5, MINUTE).await.admitted
        }));
    }
    let mut admitted = 0;
    for task in tasks {
        admitted += usize::from(task.await.unwrap());
    }
    assert_eq!(store.hits_of(&key_of(at, "203.0.113.3")).await.unwrap(), Some(16));
    assert!(admitted <= 5, "{admitted}");

    // The purge takes the closed windows and keeps the open one.
    store.insert_first("webhook:0:stale", at - Duration::hours(1)).await.unwrap();
    assert_eq!(windows.purge_closed().await.unwrap(), 1);
    assert_eq!(store.hits_of(&key_of(at, "203.0.113.1")).await.unwrap(), Some(7));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_shared_window_on_mysql() {
    rate_windows(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_shared_window_on_postgresql() {
    rate_windows(Engine::PostgreSql).await;
}

// ── SessionCleanupService, composed as the binary composes it ────────────────────────────────────────────────

async fn cleanup(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let at = now();
    let clock: SharedClock = HandClock::at(at);
    let store = SqlSignInStore::new(db.clone());
    let id = account(db, "gina", false).await;
    let sessions = credentials(db, clock.clone());
    let live = sessions.open_session(id, None, None).await.unwrap();
    execute(
        db,
        "insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at) values ('old', ?, ?, ?, ?)",
        "insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at) values ('old', $1, $2, $3, $4)",
        &[Bind::Int(id), Bind::Instant(at - Duration::days(1)), Bind::Instant(at - Duration::days(1)), Bind::Instant(at - Duration::seconds(1))],
    )
    .await;
    store.record_attempts(&["old".into()], at - Duration::minutes(31)).await.unwrap();
    store.record_attempts(&["kept".into()], at - Duration::minutes(29)).await.unwrap();
    let challenge = |hash: &str, expires| Challenge {
        token_hash: hash.into(),
        user_id: id,
        expires_at: expires,
        attempts: 0,
        user_agent: None,
        ip_address: None,
    };
    store.insert_challenge(&challenge("abandoned", at - Duration::seconds(1))).await.unwrap();
    store.insert_challenge(&challenge("waiting", at + Duration::minutes(1))).await.unwrap();
    store.insert_first("webhook:0:closed", at - Duration::seconds(1)).await.unwrap();
    store.insert_first("webhook:1:open", at + Duration::minutes(1)).await.unwrap();

    let task = session_cleanup_task(sessions.clone(), db.clone(), clock.clone());
    assert_eq!(task.sequence(), vectispire_cp_maintenance::Sequence::SessionCleanup);
    task.run().await.unwrap();

    assert_eq!(
        text(db, "select token_hash from t_session", "select token_hash from t_session").await,
        vec![live.session.token_hash]
    );
    assert_eq!(
        text(db, "select counter_key from t_login_attempt", "select counter_key from t_login_attempt").await,
        vec!["kept"]
    );
    assert_eq!(
        text(db, "select token_hash from t_mfa_challenge", "select token_hash from t_mfa_challenge").await,
        vec!["waiting"]
    );
    assert_eq!(
        text(db, "select window_key from t_rate_window", "select window_key from t_rate_window").await,
        vec!["webhook:1:open"]
    );
}

#[tokio::test]
async fn the_cleanup_on_mysql() {
    cleanup(Engine::MySql).await;
}

#[tokio::test]
async fn the_cleanup_on_postgresql() {
    cleanup(Engine::PostgreSql).await;
}
