//! `t_user` on MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`: every statement of
//! `SqlAccountStore` run against the schema the Java control plane builds, each account transaction proven to
//! commit with the sessions it closes, and a row written the way Hibernate writes it read back unchanged.
//!
//! **Docker is required, and its absence fails the test.**
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "accounts_support/mod.rs"]
mod support;

use support::{Migrated, RawCredentials};
use time::OffsetDateTime;
use time::macros::datetime;
use vectispire_cp_access::SqlAccountStore;
use vectispire_cp_access::accounts::{
    AccountStore, Accounts, Audit, AuditRecord, Clock, NewAccount, NewUser, PasswordHash, Sealed, SessionHash,
};
use vectispire_cp_access::passwords;
use vectispire_cp_db::Engine;
use vectispire_domain::secret::Secret;

const AT: OffsetDateTime = datetime!(2026-10-17 06:00:00.123456 UTC);
const LATER: OffsetDateTime = datetime!(2026-10-17 07:30:00.000001 UTC);
const PASSWORD: &str = "an invented passphrase";

struct Fixed;
impl Clock for Fixed {
    fn now(&self) -> OffsetDateTime {
        AT
    }
}

struct Nowhere;
impl Audit for Nowhere {
    async fn record(&self, _record: AuditRecord) {}
}

fn new_user(username: &str, role: &str) -> NewUser {
    NewUser {
        username: username.to_owned(),
        email: Some(format!("{username}@example.org")),
        password: Some(PasswordHash::new(passwords::hash(PASSWORD))),
        display_name: Some(format!("Display {username}")),
        role: role.to_owned(),
        is_active: true,
        must_change_password: true,
        created_at: AT,
    }
}

fn session(migrated: &Migrated, user_id: i64, token_hash: &str) {
    let statement = match migrated.engine {
        Engine::MySql => format!(
            "insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at) values \
             ('{token_hash}', {user_id}, '2026-10-17 06:00:00', '2026-10-17 06:00:00', '2099-01-01 00:00:00')"
        ),
        Engine::PostgreSql => format!(
            "insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at) values \
             ('{token_hash}', {user_id}, now(), now(), '2099-01-01 00:00:00+00')"
        ),
    };
    migrated.sql(&statement);
}

fn sessions_of(migrated: &Migrated, user_id: i64) -> Vec<String> {
    let listed =
        migrated.sql(&format!("select token_hash from t_session where user_id = {user_id} order by token_hash"));
    listed.lines().map(str::trim).filter(|line| !line.is_empty()).map(str::to_owned).collect()
}

async fn round_trip(engine: Engine) {
    let migrated = Migrated::start(engine).await;
    let db = migrated.connect().await;
    let store = SqlAccountStore::new(db.clone(), RawCredentials);

    // ── insert, read back field by field, by id and by name
    let inserted = store.insert(new_user("alice", "ADMIN")).await.unwrap();
    assert_eq!(inserted.username, "alice");
    assert_eq!(inserted.email.as_deref(), Some("alice@example.org"));
    assert_eq!(inserted.display_name.as_deref(), Some("Display alice"));
    assert_eq!(inserted.role, "ADMIN");
    assert!(inserted.is_active && inserted.must_change_password && !inserted.mfa_enabled);
    assert_eq!((inserted.created_at, inserted.updated_at), (AT, AT), "{engine}: microseconds kept, UTC");
    assert!(passwords::verify(Some(PASSWORD), inserted.password.as_ref().map(PasswordHash::encoded)));
    assert_eq!(store.find_by_username("alice").await.unwrap(), Some(inserted.clone()));
    assert_eq!(store.find_by_id(inserted.id).await.unwrap(), Some(inserted.clone()));
    assert_eq!(store.find_by_id(999_999).await.unwrap(), None);

    // ── a full save: every column, the second factor's included
    let mut changed = inserted.clone();
    changed.role = "USER".to_owned();
    changed.is_active = false;
    changed.must_change_password = false;
    changed.mfa_enabled = true;
    changed.totp_secret = Some(Sealed::new("sealed-totp-invented"));
    changed.mfa_backup_codes = Some(Sealed::new("sealed-codes-invented"));
    changed.totp_last_step = Some(59_000_123);
    changed.keycloak_id = Some("subject-alice".to_owned());
    changed.github_id = Some("4242".to_owned());
    changed.avatar_url = Some("https://example.org/a.png".to_owned());
    changed.updated_at = LATER;
    session(&migrated, inserted.id, "s-one");
    store.save(&changed, false).await.unwrap();
    assert_eq!(store.find_by_id(inserted.id).await.unwrap(), Some(changed.clone()));
    assert_eq!(sessions_of(&migrated, inserted.id), ["s-one"], "no revocation asked");
    store.save(&changed, true).await.unwrap();
    assert!(sessions_of(&migrated, inserted.id).is_empty(), "{engine}: the sessions close with the save");

    // ── one's own password: the spared session stays, the flag clears
    let bob = store.insert(new_user("bob", "USER")).await.unwrap();
    session(&migrated, bob.id, "s-kept");
    session(&migrated, bob.id, "s-other");
    let fresh = PasswordHash::new(passwords::hash("a new invented passphrase"));
    store.change_own_password(bob.id, fresh.clone(), LATER, Some(SessionHash("s-kept".to_owned()))).await.unwrap();
    let after = store.find_by_id(bob.id).await.unwrap().unwrap();
    assert_eq!(after.password, Some(fresh));
    assert!(!after.must_change_password);
    assert_eq!(after.updated_at, LATER);
    assert_eq!(sessions_of(&migrated, bob.id), ["s-kept"]);
    // With no session named, Java closes none — and neither does this.
    session(&migrated, bob.id, "s-third");
    store.change_own_password(bob.id, PasswordHash::new(passwords::hash(PASSWORD)), LATER, None).await.unwrap();
    assert_eq!(sessions_of(&migrated, bob.id), ["s-kept", "s-third"]);

    // ── everything at once, then the rehash and the counts
    store.save_revoking_everything(&after).await.unwrap();
    assert!(sessions_of(&migrated, bob.id).is_empty());
    let weaker = PasswordHash::new(passwords::hash_with(PASSWORD, 4096, 1, 1).unwrap());
    store.rehash(bob.id, weaker.clone()).await.unwrap();
    assert_eq!(store.find_by_id(bob.id).await.unwrap().unwrap().password, Some(weaker));

    store.insert(new_user("carol", "SUPERUSER")).await.unwrap();
    let dave = store.insert(new_user("dave", "ADMIN")).await.unwrap();
    // alice is inactive now; carol (SUPERUSER) and dave (ADMIN) are active administrators.
    assert_eq!(store.count_other_active_admins(&["SUPERUSER", "ADMIN"], dave.id).await.unwrap(), 1);
    assert_eq!(store.count_other_active_admins(&["SUPERUSER", "ADMIN"], 0).await.unwrap(), 2);
    let names: Vec<String> = store.all_by_username().await.unwrap().into_iter().map(|user| user.username).collect();
    assert_eq!(names, ["alice", "bob", "carol", "dave"]);
    session(&migrated, dave.id, "s-dave");
    assert_eq!(store.active_sessions_by_user(AT).await.unwrap().get(&dave.id), Some(&1));

    // ── deletion takes the sessions and the row
    store.delete(dave.id).await.unwrap();
    assert_eq!(store.find_by_id(dave.id).await.unwrap(), None);
    assert!(sessions_of(&migrated, dave.id).is_empty());

    // ── a row as Hibernate writes it: bit(1) on MySQL, datetime(6), nulls where JPA leaves them
    let raw = match engine {
        Engine::MySql => {
            "insert into t_user (username, role, is_active, created_at, updated_at, must_change_password, \
                          mfa_enabled) values ('hibernate', 'CISO', b'1', '2026-10-17 06:00:00.123456', \
                          '2026-10-17 06:00:00.123456', b'0', b'0')"
        }
        Engine::PostgreSql => {
            "insert into t_user (username, role, is_active, created_at, updated_at, \
                               must_change_password, mfa_enabled) values ('hibernate', 'CISO', true, \
                               '2026-10-17 06:00:00.123456+00', '2026-10-17 06:00:00.123456+00', false, false)"
        }
    };
    migrated.sql(raw);
    let read = store.find_by_username("hibernate").await.unwrap().unwrap();
    assert!(read.is_active && !read.must_change_password && read.password.is_none() && read.email.is_none());
    assert_eq!(read.created_at, AT);

    // ── and the service over it: a created account signs in, the bootstrap-style flag set
    let accounts = Accounts::new(SqlAccountStore::new(db.clone(), RawCredentials), Nowhere, Fixed);
    let created = accounts
        .create(
            NewAccount {
                username: Some("erin".to_owned()),
                password: Some(Secret::new(PASSWORD)),
                ..NewAccount::default()
            },
            Some(dave.id - 1),
            &Default::default(),
        )
        .await
        .unwrap();
    assert!(created.user.must_change_password);
    let signed = accounts.check_sign_in_password(Some("erin"), Some(PASSWORD)).await.unwrap();
    assert_eq!(signed.map(|user| user.id), Some(created.user.id));
    db.close().await;
}

#[tokio::test]
async fn accounts_round_trip_on_mysql() {
    round_trip(Engine::MySql).await;
}

#[tokio::test]
async fn accounts_round_trip_on_postgresql() {
    round_trip(Engine::PostgreSql).await;
}
