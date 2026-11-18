//! Four-eyes on account administration (#126, V100) on a real database: a change that makes an approver filed rather
//! than applied, approved by a second administrator under the request's lock, rejected or withdrawn, refused to an
//! approver the requester administered — and who administered whom recorded in the transaction of each gesture.
//!
//! **Docker is required, and its absence fails the test.**
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

#[path = "accounts_support/mod.rs"]
mod support;

use std::sync::{Arc, Mutex};

use support::{Migrated, RawCredentials, Sql};
use time::OffsetDateTime;
use vectispire_cp_access::SqlAccountStore;
use vectispire_cp_access::accounts::{
    AccountChange, AccountError, Accounts, ApproverIndependence, Audit, AuditRecord, Clock, IndependenceError,
    NewAccount, Outcome, RequestActor,
};
use vectispire_cp_db::Engine;
use vectispire_cp_settings::Settings;
use vectispire_domain::secret::Secret;

const PASSWORD: &str = "an invented passphrase";

struct Now;
impl Clock for Now {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<AuditRecord>>>);
impl Audit for Log {
    async fn record(&self, record: AuditRecord) {
        self.0.lock().unwrap().push(record);
    }
}

impl Log {
    fn take(&self) -> Vec<(String, String)> {
        std::mem::take(&mut *self.0.lock().unwrap())
            .into_iter()
            .map(|entry| (entry.operation.name().to_owned(), entry.description))
            .collect()
    }
}

type Service = Accounts<SqlAccountStore<RawCredentials>, Log, Now>;

fn actor(name: &str) -> RequestActor {
    RequestActor { username: Some(name.to_owned()), ..RequestActor::default() }
}

fn account(username: &str, role: &str) -> NewAccount {
    NewAccount {
        username: Some(username.to_owned()),
        password: Some(Secret::new(PASSWORD)),
        role: Some(role.to_owned()),
        ..NewAccount::default()
    }
}

/// An account written behind the service's back, so that no gesture of anybody's is recorded on it.
fn seed(migrated: &Migrated, username: &str, role: &str) -> i64 {
    let at = match migrated.engine {
        Engine::MySql => "'2026-01-01 00:00:00'",
        Engine::PostgreSql => "'2026-01-01 00:00:00+00'",
    };
    migrated.sql(&format!(
        "insert into t_user (username, role, is_active, created_at, updated_at, must_change_password, mfa_enabled) \
         values ('{username}', '{role}', true, {at}, {at}, false, false)"
    ));
    migrated.sql(&format!("select id from t_user where username = '{username}'")).trim().parse().unwrap()
}

fn gestures(migrated: &Migrated, account_id: i64) -> Vec<String> {
    migrated
        .sql(&format!(
            "select concat(administrator_id, ':', gesture) from t_account_administration where account_id = {account_id} \
             order by administrator_id, gesture"
        ))
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn four_eyes(migrated: &Migrated, on: bool) {
    migrated.sql(&format!("delete from t_setting where {q}key{q} = 'triage_four_eyes_required'", q = quote(migrated)));
    migrated.sql(&format!(
        "insert into t_setting ({q}key{q}, value) values ('triage_four_eyes_required', '{on}')",
        q = quote(migrated)
    ));
}

fn quote(migrated: &Migrated) -> &'static str {
    match migrated.engine {
        Engine::MySql => "`",
        Engine::PostgreSql => "\"",
    }
}

async fn four_eyes_on(engine: Engine) {
    let migrated = Migrated::start(engine).await;
    let db = migrated.connect().await;
    let log = Log::default();
    let settings = Arc::new(Settings::new(db.clone()));
    let accounts: Service = Accounts::new(SqlAccountStore::new(db.clone(), RawCredentials), log.clone(), Now)
        .with_four_eyes(ApproverIndependence::new(db.clone(), settings));
    let ann = seed(&migrated, "ann", "ADMIN");
    four_eyes(&migrated, true);

    // ── alone, an administrator staffs the installation: applied, and the audit says why
    let ben = accounts.create(account("ben", "ADMIN"), Some(ann), &actor("ann")).await.unwrap().applied().unwrap();
    let entries = log.take();
    assert_eq!(
        entries,
        [(
            "USER_UPDATED".to_owned(),
            "Account created: ben (ADMIN) — four-eyes: applied without a second administrator, as there is no other"
                .to_owned()
        )],
        "{engine:?}"
    );
    assert_eq!(gestures(&migrated, ben.user.id), [format!("{ann}:created")], "{engine:?}: ann made ben");

    // ── with a second administrator, a creation with a role that approves is filed
    let filed = match accounts.create(account("cid", "CISO"), Some(ann), &actor("ann")).await.unwrap() {
        Outcome::Queued(request) => request,
        Outcome::Applied(_) => panic!("{engine:?}: a CISO waits for a second administrator"),
    };
    assert_eq!((filed.kind.as_str(), filed.requested_role.as_deref()), ("create", Some("CISO")));
    assert!(filed.password_reset && filed.account_id.is_none() && filed.requested_by == "ann");
    assert_eq!(
        log.take(),
        [(
            "ACCOUNT_REQUEST_FILED".to_owned(),
            format!(
                "Account creation requested: cid (CISO) — four-eyes: waiting for another administrator (account request #{})",
                filed.id
            )
        )]
    );
    assert!(migrated.sql("select count(*) from t_user where username = 'cid'").trim() == "0", "nothing created yet");
    match accounts.create(account("cid", "CISO"), Some(ann), &actor("ann")).await {
        Err(AccountError::Conflict(message)) => {
            assert_eq!(message, "An account named \"cid\" is already waiting for approval.");
        }
        other => panic!("{engine:?}: a second filing of the same name is refused, got {other:?}"),
    }
    assert_eq!(accounts.pending(None).await.unwrap().total, 1);

    // ── nobody approves their own request; ben, whom ann made, may not approve ann's either
    assert!(matches!(accounts.approve(filed.id, Some(ann), &actor("ann")).await, Err(AccountError::OwnAccountRequest)));
    match accounts.approve(filed.id, Some(ben.user.id), &actor("ben")).await {
        Err(AccountError::Independence(IndependenceError::NotIndependent { sentence, window_days, .. })) => {
            assert_eq!(window_days, 30);
            assert_eq!(
                sentence,
                "ann created your account within the last 30 days, so you cannot approve what ann asked for: \
                 four-eyes needs an approver ann did not administer. Somebody else has to approve it."
            );
        }
        other => panic!("{engine:?}: ben is ann's second name, got {other:?}"),
    }

    // ── dee, whom nobody here administered, approves: the account exists, made by both
    let dee = seed(&migrated, "dee", "ADMIN");
    let cid = accounts.approve(filed.id, Some(dee), &actor("dee")).await.unwrap();
    assert_eq!((cid.user.username.as_str(), cid.user.role.as_str()), ("cid", "CISO"));
    assert!(cid.user.must_change_password, "{engine:?}: the typed password is a pass");
    assert_eq!(
        log.take(),
        [
            ("ACCOUNT_REQUEST_APPROVED".to_owned(), format!("Account request #{} by ann approved", filed.id)),
            (
                "USER_UPDATED".to_owned(),
                format!(
                    "Account created: cid (CISO), requested by ann and approved by dee (account request #{})",
                    filed.id
                )
            ),
        ]
    );
    let mut made = gestures(&migrated, cid.user.id);
    made.sort();
    let mut expected = vec![format!("{ann}:created"), format!("{dee}:created")];
    expected.sort();
    assert_eq!(made, expected, "{engine:?}: both administrators behind the creation are recorded");
    assert_eq!(
        migrated
            .sql(&format!("select count(*) from t_account_request where id = {} and password_hash is null", filed.id))
            .trim(),
        "1",
        "{engine:?}: the hash leaves the request once applied"
    );
    match accounts.approve(filed.id, Some(dee), &actor("dee")).await {
        Err(AccountError::Conflict(message)) => assert_eq!(message, "This request was already approved by dee."),
        other => panic!("{engine:?}: decided once, got {other:?}"),
    }

    // ── a raise is filed; deactivation sent with it applies at once
    let eve = seed(&migrated, "eve", "USER");
    let raise = AccountChange {
        role: Some("security_champion".to_owned()),
        is_active: Some(false),
        ..AccountChange::default()
    };
    let raise = match accounts.update(eve, raise, Some(ann), &actor("ann")).await.unwrap() {
        Outcome::Queued(request) => request,
        Outcome::Applied(_) => panic!("{engine:?}: a raise to an approving role waits"),
    };
    assert_eq!(raise.held_role.as_deref(), Some("USER"));
    assert_eq!(migrated.sql(&format!("select role from t_user where id = {eve}")).trim(), "USER");
    assert_eq!(
        migrated.sql(&format!("select count(*) from t_user where id = {eve} and is_active = false")).trim(),
        "1",
        "{engine:?}: the deactivation sent with the raise applied at once"
    );
    let reset =
        AccountChange { password: Some(Secret::new("another invented passphrase")), ..AccountChange::default() };
    match accounts.update(eve, reset, Some(ann), &actor("ann")).await {
        Err(AccountError::Conflict(message)) => {
            assert_eq!(message, "A change to eve is already waiting for approval: have it approved or rejected first.")
        }
        other => panic!("{engine:?}: a reset waits for the pending raise, got {other:?}"),
    }
    let entries = log.take();
    assert_eq!(entries[0], ("USER_UPDATED".to_owned(), "Account eve: deactivated".to_owned()));
    assert_eq!(entries[1].0, "ACCOUNT_REQUEST_FILED");
    assert!(entries[1].1.starts_with("Account change requested for eve: role USER → SECURITY_CHAMPION — four-eyes"));

    // ── the role moved since it was filed: stale, and nothing is written
    migrated.sql(&format!("update t_user set role = 'AUDITOR' where id = {eve}"));
    match accounts.approve(raise.id, Some(dee), &actor("dee")).await {
        Err(AccountError::Conflict(message)) => assert_eq!(
            message,
            "The role of eve changed since this request was filed: reject it, and file the change again if it is \
             still wanted."
        ),
        other => panic!("{engine:?}: a moved role makes the request stale, got {other:?}"),
    }

    // ── withdrawn by its requester, rejected by somebody else
    accounts.reject(raise.id, Some(ann), &actor("ann")).await.unwrap();
    assert_eq!(
        log.take(),
        [("ACCOUNT_REQUEST_REJECTED".to_owned(), format!("Account request #{} by ann withdrawn", raise.id))]
    );
    assert!(matches!(accounts.reject(9_999, Some(ann), &actor("ann")).await, Err(AccountError::RequestNotFound)));
    let auditor = seed(&migrated, "fay", "AUDITOR");
    assert!(matches!(
        accounts.reject(raise.id, Some(auditor), &actor("fay")).await,
        Err(AccountError::AccessDenied(message)) if message == "Only an administrator can reject an account request."
    ));

    // ── with four-eyes off, the same raise applies at once, and the gesture is recorded
    four_eyes(&migrated, false);
    let raised = accounts
        .update(
            eve,
            AccountChange { role: Some("CISO".to_owned()), ..AccountChange::default() },
            Some(ann),
            &actor("ann"),
        )
        .await
        .unwrap()
        .applied()
        .unwrap();
    assert_eq!(raised.user.role, "CISO");
    assert_eq!(gestures(&migrated, eve), [format!("{ann}:role_changed")], "{engine:?}");
    db.close().await;
}

async fn second_factor_reset(engine: Engine) {
    let migrated = Migrated::start(engine).await;
    let db = migrated.connect().await;
    let log = Log::default();
    let accounts: Service = Accounts::new(SqlAccountStore::new(db.clone(), RawCredentials), log.clone(), Now);
    let ann = seed(&migrated, "ann", "ADMIN");
    let gus = seed(&migrated, "gus", "USER");
    migrated.sql(&format!(
        "update t_user set mfa_enabled = true, totp_secret = 'sealed', mfa_backup_codes = 'sealed', totp_last_step = 7 \
         where id = {gus}"
    ));

    assert!(matches!(
        accounts.reset_second_factor(ann, Some(ann), &actor("ann")).await,
        Err(AccountError::InvalidInput(message))
            if message == "You cannot reset your own second factor: disable it with a current code."
    ));
    assert!(matches!(
        accounts.reset_second_factor(ann, Some(gus), &actor("gus")).await,
        Err(AccountError::AccessDenied(message))
            if message == "Only an administrator can reset another account's second factor."
    ));
    let reset = accounts.reset_second_factor(gus, Some(ann), &actor("ann")).await.unwrap();
    assert!(!reset.user.mfa_enabled);
    assert_eq!(
        migrated
            .sql(&format!(
                "select count(*) from t_user where id = {gus} and totp_secret is null and mfa_backup_codes is null \
                 and totp_last_step is null"
            ))
            .trim(),
        "1",
        "{engine:?}: every secret of the factor is gone"
    );
    assert_eq!(
        log.take(),
        [(
            "USER_UPDATED".to_owned(),
            "Account gus: second factor reset by an administrator, sessions closed".to_owned()
        )]
    );
    // Idempotent: nothing to reset, nothing written.
    accounts.reset_second_factor(gus, Some(ann), &actor("ann")).await.unwrap();
    assert!(log.take().is_empty());
    db.close().await;
}

#[tokio::test]
async fn four_eyes_on_mysql() {
    if vectispire_cp_db::testing::runs_on(Engine::MySql) {
        four_eyes_on(Engine::MySql).await;
    }
}

#[tokio::test]
async fn four_eyes_on_postgresql() {
    if vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        four_eyes_on(Engine::PostgreSql).await;
    }
}

#[tokio::test]
async fn second_factor_reset_on_mysql() {
    if vectispire_cp_db::testing::runs_on(Engine::MySql) {
        second_factor_reset(Engine::MySql).await;
    }
}

#[tokio::test]
async fn second_factor_reset_on_postgresql() {
    if vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        second_factor_reset(Engine::PostgreSql).await;
    }
}
