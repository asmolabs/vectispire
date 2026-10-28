//! Sessions, API keys, agent keys and the SCIM token against real databases — MySQL 9.4 and PostgreSQL 17, each
//! migrated by the Rust runner from the repository's migrations. Every statement the credentials make runs here on
//! both engines; the cross-switch proof against the Java control plane is `across_the_switch.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use support::{Bind, HandClock, Migrated, account, agent, execute};
use time::Duration;
use vectispire_cp_access::credentials::{
    Clock, CredentialService, IssueError, IssueRefusal, IssuerSees, KeyRequest, Resolved, ScimToken, SessionPolicy,
    StoreError, hash_of, keys, phc,
};
use vectispire_cp_db::{Db, Engine, ScanTarget, Visibility};
use vectispire_cp_http::credentials::{BoxFuture, Credentials};
use vectispire_cp_http::principal::Credential;
use vectispire_cp_http::{ApiKeyScope, Role};
use vectispire_domain::secret::Secret;

/// The issuer sees repository 7 and nothing else — what `GrantableTargets` and `VisibilityService` will answer.
struct SeesSeven;

impl IssuerSees for SeesSeven {
    fn issuer_sees<'a>(&'a self, _issuer: i64, target: ScanTarget) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move { Ok(target == ScanTarget::Repository(7)) })
    }
}

fn service(db: &Db, clock: Arc<HandClock>, scim: ScimToken) -> CredentialService {
    CredentialService::new(
        db.clone(),
        clock,
        SessionPolicy::default(),
        Arc::new(support::AgentsTable(db.clone())),
        scim,
    )
}

async fn count(db: &Db, table: &str) -> i64 {
    let sql = format!("select count(*) from {table}");
    match db {
        Db::MySql(pool) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_one(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).fetch_one(pool).await.unwrap(),
    }
}

async fn stored_session_hashes(db: &Db) -> Vec<String> {
    match db {
        Db::MySql(pool) => sqlx::query_scalar("select token_hash from t_session").fetch_all(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar("select token_hash from t_session").fetch_all(pool).await.unwrap(),
    }
}

async fn sessions(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let clock = HandClock::at(support::now());
    let credentials = service(db, clock.clone(), ScimToken::default());
    let alice = account(db, "alice", "ADMIN", true, false).await;

    // ── Opened, resolved, and only the hash stored.
    let issued = credentials.open_session(alice, Some(&"agent ".repeat(80)), Some("192.0.2.4")).await.unwrap();
    let token = issued.token.expose().to_owned();
    assert_eq!(stored_session_hashes(db).await, vec![hash_of(&token)], "the store holds the hash, never the token");
    assert_eq!(
        issued.session.user_agent.as_deref().map(str::len),
        Some(255),
        "the user agent is clipped to the column"
    );
    let principal = credentials.session(&token).await.expect("the session resolves");
    assert_eq!(principal.credential, Credential::Session);
    let account_seen = principal.account.unwrap();
    assert_eq!((account_seen.username.as_str(), account_seen.role), ("alice", Some(Role::Admin)));
    assert!(credentials.session(&issued.session.token_hash).await.is_none(), "the stored hash authenticates nobody");
    assert!(credentials.session(&format!("{token} x")).await.is_none(), "a token with a space is no session token");

    // ── Activity at the grain: 59 s writes nothing, 60 s does.
    let first_seen = issued.session.last_seen_at;
    clock.advance(Duration::seconds(59));
    let Some(Resolved::Session { session, .. }) = credentials.authenticate_session(&token).await.unwrap() else {
        panic!("still a session");
    };
    assert_eq!(session.last_seen_at, first_seen);
    clock.advance(Duration::seconds(1));
    let Some(Resolved::Session { session, .. }) = credentials.authenticate_session(&token).await.unwrap() else {
        panic!("still a session");
    };
    assert_eq!(session.last_seen_at, first_seen + Duration::seconds(60));
    assert_eq!(
        credentials.resolve_session(&token).await.unwrap().unwrap().last_seen_at,
        first_seen + Duration::seconds(60)
    );

    // ── Idle: an hour of silence closes it, and the row is deleted rather than kept.
    clock.advance(Duration::minutes(60));
    assert!(credentials.session(&token).await.is_none());
    assert_eq!(count(db, "t_session").await, 0, "an idle session is deleted");

    // ── Absolute: busy the whole time, twelve hours still end it.
    let busy = credentials.open_session(alice, None, None).await.unwrap();
    for _ in 0..24 {
        clock.advance(Duration::minutes(30));
        if credentials.session(busy.token.expose()).await.is_none() {
            break;
        }
    }
    assert!(credentials.session(busy.token.expose()).await.is_none());
    assert_eq!(count(db, "t_session").await, 0);

    // ── A deactivated account's session is closed, not honoured until it expires.
    let bob = account(db, "bob", "USER", true, true).await;
    let bobs = credentials.open_session(bob, None, None).await.unwrap();
    let principal = credentials.session(bobs.token.expose()).await.unwrap();
    assert!(principal.must_change_password(), "the account's pending password change travels with it");
    execute(
        db,
        "update t_user set is_active = false where id = ?",
        "update t_user set is_active = false where id = $1",
        &[Bind::Int(bob)],
    )
    .await;
    assert!(credentials.session(bobs.token.expose()).await.is_none());
    assert_eq!(count(db, "t_session").await, 0, "and its row is gone");

    // ── An unreadable role authorizes nothing, and is not mistaken for the least privileged one.
    let carol = account(db, "carol", "admin", true, false).await;
    let carols = credentials.open_session(carol, None, None).await.unwrap();
    assert_eq!(credentials.session(carols.token.expose()).await.unwrap().role(), None);

    // ── Every session of an account, then all but one.
    let a = credentials.open_session(alice, None, None).await.unwrap();
    let b = credentials.open_session(alice, None, None).await.unwrap();
    let c = credentials.open_session(alice, None, None).await.unwrap();
    assert_eq!(credentials.revoke_others(alice, &b.session.token_hash).await.unwrap(), 2);
    assert!(credentials.session(b.token.expose()).await.is_some());
    assert!(
        credentials.session(a.token.expose()).await.is_none() && credentials.session(c.token.expose()).await.is_none()
    );
    let counted = credentials.count_active_by_user().await.unwrap();
    assert!(counted.contains(&(alice, 1)) && counted.contains(&(carol, 1)), "{counted:?}");
    assert_eq!(credentials.revoke_all_for_user(alice).await.unwrap(), 1);
    assert!(credentials.session(b.token.expose()).await.is_none());
    credentials.revoke(&carols.session).await.unwrap();
    assert_eq!(count(db, "t_session").await, 0);

    // ── The purge: past the absolute lifetime, untouched rows go.
    let stale = credentials.open_session(alice, None, None).await.unwrap();
    let kept = {
        clock.advance(Duration::hours(6));
        credentials.open_session(alice, None, None).await.unwrap()
    };
    clock.advance(Duration::hours(6) + Duration::seconds(1));
    assert_eq!(credentials.purge_expired().await.unwrap(), 1);
    assert_eq!(stored_session_hashes(db).await, vec![kept.session.token_hash.clone()]);
    let _ = stale;
    credentials.revoke_all_for_user(alice).await.unwrap();

    // ── The single sign-on hand-off: not a bearer token, exchanged once, dead after a minute.
    let handoff = credentials.open_handoff(alice, Some("browser"), Some("192.0.2.9")).await.unwrap();
    assert!(credentials.session(handoff.token.expose()).await.is_none(), "a hand-off opens no API");
    let waiting = credentials.resolve_handoff(handoff.token.expose()).await.unwrap().expect("waiting");
    let exchanged = credentials.exchange_once(&waiting).await.unwrap().expect("the first exchange");
    assert!(credentials.exchange_once(&waiting).await.unwrap().is_none(), "the second exchange gets nothing");
    assert_eq!(exchanged.session.user_agent.as_deref(), Some("browser"));
    assert!(credentials.session(exchanged.token.expose()).await.is_some());
    let late = credentials.open_handoff(alice, None, None).await.unwrap();
    clock.advance(Duration::seconds(60));
    assert!(
        credentials.resolve_handoff(late.token.expose()).await.unwrap().is_some(),
        "sixty seconds are still in time"
    );
    clock.advance(Duration::microseconds(1));
    assert!(credentials.resolve_handoff(late.token.expose()).await.unwrap().is_none());
    assert!(credentials.resolve_handoff("  ").await.unwrap().is_none());
}

async fn api_keys(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = &database.db;
    let clock = HandClock::at(support::now());
    let scim = ScimToken { enabled: true, token: Some(Secret::new("invented-scim-token-for-the-test")) };
    let credentials = service(db, clock.clone(), scim);
    let owner = account(db, "pipeline-owner", "SECURITY_CHAMPION", true, false).await;

    // ── Issued: the defaults, the prefix in the clear, the hash an Argon2id PHC string of the whole key.
    let issued = credentials
        .issue_integration_key(owner, &KeyRequest { name: Some("  ci  ".into()), ..KeyRequest::default() }, &SeesSeven)
        .await
        .unwrap();
    let secret = issued.secret.expose().to_owned();
    assert_eq!(issued.key.name, "ci");
    assert_eq!(issued.key.scopes, "read,scan,export");
    assert_eq!(issued.key.prefix.as_deref(), keys::lookup_prefix(&secret));
    assert_eq!(issued.audit_description, "API key issued: ci (read,scan,export)");
    let (hash,): (String,) = match db {
        Db::MySql(pool) => sqlx::query_as("select key_hash from t_api_key").fetch_one(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_as("select key_hash from t_api_key").fetch_one(pool).await.unwrap(),
    };
    assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$") && !hash.contains(&secret));
    assert!(phc::verify(&secret, &hash));

    // ── Resolved through the chain's trait: the account, the key's id, its scopes; last use recorded.
    assert!(issued.key.last_used_at.is_none());
    let principal = credentials.api_key(&format!("  {secret} ")).await.expect("the key, trimmed");
    assert_eq!(principal.account.as_ref().unwrap().username, "pipeline-owner");
    assert_eq!(
        principal.credential,
        Credential::Integration {
            key_id: issued.key.id.as_hyphenated().to_string(),
            scopes: vec![ApiKeyScope::Read, ApiKeyScope::Scan, ApiKeyScope::Export]
        }
    );
    assert_eq!(credentials.key(issued.key.id).await.unwrap().unwrap().last_used_at, Some(clock.now()));
    assert!(credentials.api_key(&secret[..secret.len() - 1]).await.is_none(), "one character short");
    assert!(credentials.api_key(&secret[..12]).await.is_none(), "the prefix alone");
    assert!(credentials.session(&secret).await.is_none(), "a key is not a session");

    // ── A restricted key carries its restriction, and the attribution names the key.
    let restricted = credentials
        .issue_integration_key(
            owner,
            &KeyRequest {
                name: Some("one repo".into()),
                scopes: Some(vec![Some("read".into()), None, Some(" SARIF_IMPORT ".into())]),
                target_kind: Some("Repository".into()),
                target_id: Some(7),
                expires_in_days: Some(1),
            },
            &SeesSeven,
        )
        .await
        .unwrap();
    assert_eq!(restricted.key.scopes, "read,sarif_import");
    let Some(Resolved::Integration(integration)) =
        credentials.authenticate_key(restricted.secret.expose()).await.unwrap()
    else {
        panic!("an integration")
    };
    assert_eq!(integration.restriction, Visibility::only([ScanTarget::Repository(7)]));
    assert_eq!(
        Resolved::Integration(integration.clone()).credential_restriction(),
        Visibility::only([ScanTarget::Repository(7)])
    );
    assert_eq!(Resolved::Integration(integration.clone()).actor(), "pipeline-owner (API key one repo)");
    // …and the principal the chain hands the routes carries all three: the account, the restriction every scoped
    // route intersects with it, and the attribution.
    let grounds = Resolved::Integration(integration).principal().grounds;
    assert_eq!(grounds.account_id, Some(owner));
    assert_eq!(
        grounds.restriction,
        vectispire_cp_http::Restriction::Target(vectispire_domain::ScanTarget::Repository(7))
    );
    assert_eq!(grounds.actor.as_deref(), Some("pipeline-owner (API key one repo)"));
    assert!(grounds.stored_role.is_some());

    // ── Expired: refused, its row kept, and its last use not moved.
    let before = credentials.key(restricted.key.id).await.unwrap().unwrap().last_used_at;
    clock.advance(Duration::days(1));
    assert!(credentials.api_key(restricted.secret.expose()).await.is_none());
    let row = credentials.key(restricted.key.id).await.unwrap().expect("the row is kept for the audit trail");
    assert_eq!(row.last_used_at, before);
    assert!(row.is_expired(clock.now()));

    // ── Refusals, with the Java sentences.
    let refuse = |request: KeyRequest| {
        let credentials = credentials.clone();
        async move { credentials.issue_integration_key(owner, &request, &SeesSeven).await }
    };
    let message = |outcome: Result<_, IssueError>| match outcome {
        Err(IssueError::Refused(IssueRefusal::InvalidKey(message) | IssueRefusal::InvalidInput(message))) => message,
        other => panic!("refused, not {other:?}"),
    };
    assert_eq!(
        message(
            refuse(KeyRequest {
                name: Some("a".into()),
                scopes: Some(vec![Some("agent".into())]),
                ..KeyRequest::default()
            })
            .await
        ),
        "The agent scope is not issued here: declare the agent, which creates its key."
    );
    assert_eq!(
        message(
            refuse(KeyRequest {
                name: Some("a".into()),
                target_kind: Some("repository".into()),
                target_id: Some(8),
                ..KeyRequest::default()
            })
            .await
        ),
        "No repository 8 to restrict the key to."
    );
    assert_eq!(message(refuse(KeyRequest::default()).await), "A name is required.");
    assert_eq!(count(db, "t_api_key").await, 2, "a refused key writes nothing");

    // ── The owner deactivated: its keys stop, they do not outlive the authority they borrow.
    execute(
        db,
        "update t_user set is_active = false where id = ?",
        "update t_user set is_active = false where id = $1",
        &[Bind::Int(owner)],
    )
    .await;
    assert!(credentials.api_key(&secret).await.is_none());
    execute(
        db,
        "update t_user set is_active = true where id = ?",
        "update t_user set is_active = true where id = $1",
        &[Bind::Int(owner)],
    )
    .await;
    assert!(credentials.api_key(&secret).await.is_some());

    // ── An agent's key is its agent; with no agent behind it, nobody — never an integration.
    let (agent_key_id, agent_secret) = credentials.issue_agent_key("builder-01").await.unwrap();
    assert!(credentials.api_key(agent_secret.expose()).await.is_none(), "no agent row yet");
    agent(db, "builder-01", agent_key_id).await;
    let principal = credentials.api_key(agent_secret.expose()).await.expect("the agent");
    assert_eq!(principal.credential, Credential::Agent { agent: "agent:builder-01".into() });
    assert!(principal.account.is_none());
    // A key with the agent scope and an owner is still not an integration.
    execute(
        db,
        "update t_api_key set owner_user_id = ? where id = ?",
        "update t_api_key set owner_user_id = $1 where id = $2",
        &[Bind::Int(owner), Bind::Text(&agent_key_id.as_hyphenated().to_string())],
    )
    .await;
    let key = credentials.resolve_key(agent_secret.expose()).await.unwrap().unwrap();
    assert!(credentials.integration_for(&key).await.unwrap().is_none());
    // And with its agent gone it is nobody — not the owner's integration key.
    execute(db, "delete from t_agent where name = 'builder-01'", "delete from t_agent where name = 'builder-01'", &[])
        .await;
    assert!(credentials.api_key(agent_secret.expose()).await.is_none());

    // ── A key issued before keys had an owner acts for nobody.
    execute(
        db,
        "update t_api_key set owner_user_id = null where id = ?",
        "update t_api_key set owner_user_id = null where id = $1",
        &[Bind::Text(&issued.key.id.as_hyphenated().to_string())],
    )
    .await;
    assert!(credentials.api_key(&secret).await.is_none());

    // ── Two keys under one prefix: each verifies against its own hash.
    let twin = keys::generate();
    let twin_secret = format!("{}{}", &secret[..12], &twin.full_key.expose()[12..]);
    let twin_id = support::random_id();
    execute(
        db,
        "insert into t_api_key (id, name, key_hash, prefix, created_at, scopes, owner_user_id) values (?, 'twin', ?, ?, ?, 'read', ?)",
        "insert into t_api_key (id, name, key_hash, prefix, created_at, scopes, owner_user_id) values ($1, 'twin', $2, $3, $4, 'read', $5)",
        &[Bind::Text(&twin_id), Bind::Text(&phc::hash(&twin_secret)), Bind::Text(&secret[..12]), Bind::Instant(clock.now()), Bind::Int(owner)],
    )
    .await;
    let principal = credentials.api_key(&twin_secret).await.expect("the twin");
    assert!(matches!(principal.credential, Credential::Integration { ref key_id, .. } if *key_id == twin_id));

    // ── Revoked: the row goes, and so does every key an account issued.
    assert!(credentials.revoke_key(restricted.key.id).await.unwrap());
    assert!(!credentials.revoke_key(restricted.key.id).await.unwrap());
    assert_eq!(credentials.revoke_keys_owned_by(owner).await.unwrap(), 2, "the twin and the agent's re-owned key");
    assert!(credentials.api_key(&twin_secret).await.is_none());

    // ── SCIM: on, the token matches; off, the same token is nothing.
    assert!(credentials.scim("invented-scim-token-for-the-test").await);
    assert!(!credentials.scim("invented-scim-token-for-the-tes").await);
    let off =
        service(db, clock, ScimToken { enabled: false, token: Some(Secret::new("invented-scim-token-for-the-test")) });
    assert!(!off.scim("invented-scim-token-for-the-test").await);
}

#[tokio::test]
async fn sessions_on_mysql() {
    sessions(Engine::MySql).await;
}

#[tokio::test]
async fn sessions_on_postgresql() {
    sessions(Engine::PostgreSql).await;
}

#[tokio::test]
async fn api_keys_on_mysql() {
    api_keys(Engine::MySql).await;
}

#[tokio::test]
async fn api_keys_on_postgresql() {
    api_keys(Engine::PostgreSql).await;
}
