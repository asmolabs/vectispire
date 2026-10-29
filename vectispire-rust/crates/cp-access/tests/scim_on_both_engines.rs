//! SCIM provisioning on MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`: every statement of
//! `persistence/scim.rs` and the administration's it reuses, then the Java tests that hold the service —
//! `ScimUsersRoutesTest`, `ScimGroupsRoutesTest`, `ScimPagingRoutesTest`, `ScimUsersControllerTest` — case by case, with
//! every sentence and audit entry word for word, and the transactions: a statement refused half-way through a gesture
//! (a trigger the test sets as the server's administrator) leaves nothing of it written.
//!
//! **Docker is required, and its absence fails the test.**

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines, clippy::indexing_slicing)]

#[path = "accounts_support/mod.rs"]
mod accounts_support;
mod support;

use std::sync::{Arc, Mutex};

use accounts_support::{Migrated, Sql};
use serde_json::{Value, json};
use support::{Bind, HandClock, execute};
use uuid::Uuid;
use vectispire_cp_access::accounts::{Audit, AuditOperation, AuditRecord, RequestActor, UserView};
use vectispire_cp_access::credentials::Clock;
use vectispire_cp_access::scim::{
    GroupChange, GroupCreation, GroupView, PatchOperation, ScimError, ScimParts, ScimProvisioning, UserAttributes,
    UserChange, UserCreation,
};
use vectispire_cp_db::{Db, Engine};

/// Well past anything a test creates, and never handed out: the engines do not reuse ids.
const ABSENT: i64 = 987_654_321;

// ── doubles and fixture ──────────────────────────────────────────────────────────────────────────────────────────────

/// The audit log, keeping its entries.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<AuditRecord>>>);

impl Log {
    fn take(&self) -> Vec<AuditRecord> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

impl Audit for Log {
    async fn record(&self, record: AuditRecord) {
        self.0.lock().unwrap().push(record);
    }
}

type SharedClock = Arc<dyn Clock>;

struct Fixture {
    database: Migrated,
    db: Db,
    log: Log,
    clock: Arc<HandClock>,
}

impl Fixture {
    async fn start(engine: Engine) -> Fixture {
        let database = Migrated::start(engine).await;
        let db = database.connect().await;
        Fixture { database, db, log: Log::default(), clock: HandClock::at(support::now()) }
    }

    fn scim(&self) -> ScimProvisioning<Log, SharedClock> {
        self.provisioning(false)
    }

    fn provisioning(&self, link_privileged: bool) -> ScimProvisioning<Log, SharedClock> {
        ScimProvisioning::new(ScimParts {
            db: self.db.clone(),
            audit: self.log.clone(),
            clock: self.clock.clone(),
            link_privileged,
        })
    }

    fn engine(&self) -> Engine {
        self.database.engine
    }
}

/// `RequestActors.unnamed(request)`: the directory has no account, only an address and an agent.
fn directory() -> RequestActor {
    RequestActor { username: None, ip_address: Some("203.0.113.9".to_owned()), user_agent: Some("okta".to_owned()) }
}

/// The entry Java writes for a SCIM gesture: under `SCIM`, attributed to the account's or the team's name.
fn entry(operation: AuditOperation, name: &str, description: impl Into<String>) -> AuditRecord {
    let actor = directory();
    AuditRecord {
        operation,
        resource: "SCIM".to_owned(),
        description: description.into(),
        username: Some(name.to_owned()),
        ip_address: actor.ip_address,
        user_agent: actor.user_agent,
        signal: None,
    }
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", &Uuid::new_v4().simple().to_string()[..12])
}

async fn count(db: &Db, sql: &str) -> i64 {
    let sql = sqlx::AssertSqlSafe(sql.to_owned());
    match db {
        Db::MySql(pool) => sqlx::query_scalar(sql).fetch_one(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar(sql).fetch_one(pool).await.unwrap(),
    }
}

async fn text(db: &Db, sql: &str) -> Option<String> {
    let sql = sqlx::AssertSqlSafe(sql.to_owned());
    match db {
        Db::MySql(pool) => sqlx::query_scalar(sql).fetch_one(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar(sql).fetch_one(pool).await.unwrap(),
    }
}

/// An account as the accounts module writes one; answers its id and its name.
async fn account(db: &Db, prefix: &str, role: &str) -> (i64, String) {
    let name = unique(prefix);
    (support::account(db, &name, role, true, false).await, name)
}

async fn role_of(db: &Db, id: i64) -> String {
    text(db, &format!("select role from t_user where id = {id}")).await.unwrap()
}

async fn subject_of(db: &Db, id: i64) -> Option<String> {
    text(db, &format!("select keycloak_id from t_user where id = {id}")).await
}

async fn display_name_of(db: &Db, id: i64) -> Option<String> {
    text(db, &format!("select display_name from t_user where id = {id}")).await
}

async fn is_active(db: &Db, id: i64) -> bool {
    count(db, &format!("select count(*) from t_user where id = {id} and is_active = true")).await == 1
}

async fn exists(db: &Db, id: i64) -> bool {
    count(db, &format!("select count(*) from t_user where id = {id}")).await == 1
}

/// A live session of the account, as `AuthService` writes one.
async fn session(db: &Db, user_id: i64) {
    let now = support::now();
    execute(
        db,
        "insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at) values (?, ?, ?, ?, ?)",
        "insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at) \
         values ($1, $2, $3, $4, $5)",
        &[
            Bind::Text(&support::random_id()),
            Bind::Int(user_id),
            Bind::Instant(now),
            Bind::Instant(now),
            Bind::Instant(now + time::Duration::days(1)),
        ],
    )
    .await;
}

async fn sessions(db: &Db, user_id: i64) -> i64 {
    count(db, &format!("select count(*) from t_session where user_id = {user_id}")).await
}

async fn team(db: &Db, name: &str) -> i64 {
    execute(
        db,
        "insert into t_team (name, created_at) values (?, ?)",
        "insert into t_team (name, created_at) values ($1, $2)",
        &[Bind::Text(name), Bind::Instant(support::now())],
    )
    .await;
    count(db, "select max(id) from t_team").await
}

async fn team_name(db: &Db, id: i64) -> String {
    text(db, &format!("select name from t_team where id = {id}")).await.unwrap()
}

async fn member(db: &Db, team_id: i64, user_id: i64, origin: &str) {
    execute(
        db,
        "insert into t_team_member (team_id, user_id, origin) values (?, ?, ?)",
        "insert into t_team_member (team_id, user_id, origin) values ($1, $2, $3)",
        &[Bind::Int(team_id), Bind::Int(user_id), Bind::Text(origin)],
    )
    .await;
}

/// The team's rows as `user:origin`, by account.
async fn members(db: &Db, team_id: i64) -> Vec<String> {
    let sql = sqlx::AssertSqlSafe(format!(
        "select user_id, origin from t_team_member where team_id = {team_id} order by user_id"
    ));
    let rows: Vec<(i64, String)> = match db {
        Db::MySql(pool) => sqlx::query_as(sql).fetch_all(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_as(sql).fetch_all(pool).await.unwrap(),
    };
    rows.into_iter().map(|(user, origin)| format!("{user}:{origin}")).collect()
}

fn attributes(user_name: &str) -> UserAttributes {
    UserAttributes { user_name: Some(user_name.to_owned()), ..UserAttributes::default() }
}

fn operation(op: &str, path: Option<&str>, value: Option<Value>) -> PatchOperation {
    PatchOperation { op: Some(op.to_owned()), path: path.map(str::to_owned), value }
}

fn invalid<T: std::fmt::Debug>(result: Result<T, ScimError>) -> String {
    match result {
        Err(ScimError::InvalidInput(message)) => message,
        other => panic!("expected a 400, got {other:?}"),
    }
}

fn protected<T: std::fmt::Debug>(result: Result<T, ScimError>) -> String {
    match result {
        Err(ScimError::ProtectedAccount(message)) => message,
        other => panic!("expected a 403, got {other:?}"),
    }
}

fn failed<T: std::fmt::Debug>(result: Result<T, ScimError>) {
    assert!(matches!(result, Err(ScimError::Failed(_))), "expected a failure, got {result:?}");
}

fn created(outcome: UserCreation) -> UserView {
    match outcome {
        UserCreation::Created(user) => *user,
        other => panic!("expected an account, got {other:?}"),
    }
}

fn changed(outcome: UserChange) -> UserView {
    match outcome {
        UserChange::Changed(user) => *user,
        other => panic!("expected an account, got {other:?}"),
    }
}

fn group_created(outcome: GroupCreation) -> GroupView {
    match outcome {
        GroupCreation::Created(group) => group,
        other => panic!("expected a group, got {other:?}"),
    }
}

fn group_changed(outcome: GroupChange) -> GroupView {
    match outcome {
        GroupChange::Changed(group) => group,
        other => panic!("expected a group, got {other:?}"),
    }
}

fn member_ids(group: &GroupView) -> Vec<i64> {
    group.members.iter().map(|member| member.user_id).collect()
}

// ── ScimUsersRoutesTest, ScimUsersControllerTest ─────────────────────────────────────────────────────────────────────

/// A PATCH setting `active` to false deactivates the account and closes its sessions; nothing else is recorded.
async fn a_patch_deactivates_and_closes_the_sessions(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (id, name) = account(db, "scim-leaver", "USER").await;
    session(db, id).await;
    session(db, id).await;

    // A display name, by an object value: no entry, the sessions stay.
    let renamed = scim
        .patch_user(id, Some(&[operation("replace", None, Some(json!({ "displayName": "Renamed" })))]), &directory())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(renamed.display_name.as_deref(), Some("Renamed"));
    assert_eq!(display_name_of(db, id).await.as_deref(), Some("Renamed"));
    assert_eq!(sessions(db, id).await, 2);
    assert!(fixture.log.take().is_empty(), "only a deactivation is recorded");

    // The path is read in any case.
    let left = scim
        .patch_user(id, Some(&[operation("replace", Some("Active"), Some(json!(false)))]), &directory())
        .await
        .unwrap()
        .unwrap();
    assert!(!left.is_active);
    assert!(!is_active(db, id).await);
    assert_eq!(sessions(db, id).await, 0, "out when the directory says so");
    assert_eq!(
        fixture.log.take(),
        vec![entry(
            AuditOperation::UserUpdated,
            &name,
            format!("SCIM deactivated account and revoked active sessions for {name}")
        )]
    );

    // Back on through an object value, and an operation the service does not read changes nothing.
    let back = scim
        .patch_user(
            id,
            Some(&[operation("replace", None, Some(json!({ "active": true }))), operation("add", Some("title"), None)]),
            &directory(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(back.is_active && is_active(db, id).await);
    assert!(fixture.log.take().is_empty());
}

/// An administrative account cannot be replaced, patched or deleted through SCIM, and keeps what it had.
async fn administrative_accounts_are_protected(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    for role in ["ADMIN", "SUPERUSER"] {
        let (id, name) = account(db, "scim-admin", role).await;
        let sentence = format!(
            "The account \"{name}\" holds an administrative role and is administered in Vectispire, not through SCIM."
        );
        let rebind = UserAttributes { external_id: Some("attacker-subject".to_owned()), ..attributes(&name) };
        assert_eq!(protected(scim.replace_user(id, &rebind, &directory()).await), sentence);
        assert_eq!(
            protected(
                scim.patch_user(id, Some(&[operation("replace", Some("active"), Some(json!(false)))]), &directory())
                    .await
            ),
            sentence
        );
        assert_eq!(protected(scim.delete_user(id, &directory()).await), sentence);
        assert_eq!(subject_of(db, id).await, None);
        assert!(is_active(db, id).await);
        assert_eq!(role_of(db, id).await, role);
    }
    assert!(fixture.log.take().is_empty());
}

/// A PATCH or an attribute past its column is refused with its sentence, and nothing is written.
async fn an_attribute_past_its_column_is_refused(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (id, _) = account(db, "scim-patched", "USER").await;
    let long = "d".repeat(256);
    assert_eq!(
        invalid(
            scim.patch_user(
                id,
                Some(&[operation("replace", None, Some(json!({ "displayName": long })))]),
                &directory()
            )
            .await
        ),
        "The SCIM attribute displayName is longer than 255 characters."
    );
    assert_eq!(display_name_of(db, id).await, None);

    // Counted in UTF-16 units: 128 emoji are 256 of them.
    let emoji = "😀".repeat(128);
    for (field, refused) in [
        ("emails", UserAttributes { email: Some(emoji.clone()), ..attributes("scim-too-long") }),
        ("externalId", UserAttributes { external_id: Some("x".repeat(256)), ..attributes("scim-too-long") }),
        ("displayName", UserAttributes { display_name: Some(long.clone()), ..attributes("scim-too-long") }),
    ] {
        assert_eq!(
            invalid(scim.create_user(&refused, &directory()).await),
            format!("The SCIM attribute {field} is longer than 255 characters.")
        );
        assert!(invalid(scim.replace_user(id, &refused, &directory()).await).contains(field));
    }
    assert_eq!(count(db, "select count(*) from t_user where username = 'scim-too-long'").await, 0);
    // At the width, accepted.
    let fits = UserAttributes { email: Some("😀".repeat(127)), ..attributes(&unique("scim-fits")) };
    assert_eq!(created(scim.create_user(&fits, &directory()).await.unwrap()).email, fits.email);
    fixture.log.take();
}

/// SCIM grants only the scoped roles; one that administers or sees the whole estate is Vectispire's.
async fn only_scoped_roles_are_granted(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    for (requested, granted) in [
        ("USER", Some("USER")),
        ("SECURITY_CHAMPION", Some("SECURITY_CHAMPION")),
        (" security_champion ", Some("SECURITY_CHAMPION")),
        ("WIZARD", Some("USER")),
        ("ADMIN", None),
        ("admin", None),
        ("SUPERUSER", None),
        ("CISO", None),
        ("AUDITOR", None),
    ] {
        let name = unique("scim-role");
        let request = UserAttributes { role: Some(requested.to_owned()), ..attributes(&name) };
        let outcome = scim.create_user(&request, &directory()).await;
        let stored = count(db, &format!("select count(*) from t_user where username = '{name}'")).await;
        match granted {
            Some(role) => {
                assert_eq!(created(outcome.unwrap()).role, role, "{requested}");
                assert_eq!(stored, 1);
            }
            None => {
                let role = requested.trim().to_uppercase();
                assert_eq!(
                    invalid(outcome),
                    format!(
                        "SCIM cannot grant the {role} role: roles that administer or see the whole estate are granted \
                         in Vectispire."
                    )
                );
                assert_eq!(stored, 0, "{requested}");
            }
        }
    }

    // On a replacement too.
    let (plain, name) = account(db, "scim-plain", "USER").await;
    let promote = UserAttributes { role: Some("SUPERUSER".to_owned()), ..attributes(&name) };
    invalid(scim.replace_user(plain, &promote, &directory()).await);
    assert_eq!(role_of(db, plain).await, "USER");
    fixture.log.take();
}

/// Naming the role an account already holds is not a grant; a replacement naming none keeps it.
async fn the_held_role_is_no_grant_and_no_role_no_demotion(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (auditor, name) = account(db, "scim-auditor", "AUDITOR").await;
    let same = UserAttributes { role: Some("AUDITOR".to_owned()), ..attributes(&name) };
    assert_eq!(changed(scim.replace_user(auditor, &same, &directory()).await.unwrap()).role, "AUDITOR");
    let ciso = UserAttributes { role: Some("CISO".to_owned()), ..attributes(&name) };
    invalid(scim.replace_user(auditor, &ciso, &directory()).await);
    assert_eq!(role_of(db, auditor).await, "AUDITOR");

    let (chief, name) = account(db, "scim-ciso", "CISO").await;
    let renamed = UserAttributes { display_name: Some("Renamed".to_owned()), ..attributes(&name) };
    let view = changed(scim.replace_user(chief, &renamed, &directory()).await.unwrap());
    assert_eq!((view.role.as_str(), view.is_active), ("CISO", true), "an absent role and an absent active");
    assert_eq!(role_of(db, chief).await, "CISO");
    assert!(is_active(db, chief).await);
    assert_eq!(fixture.log.take().last().unwrap().description, format!("SCIM updated account: {name}"));
}

/// `externalId` is bound once and never rebound; the binding the account has passes.
async fn an_external_id_is_bound_once(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (id, name) = account(db, "scim-bound", "USER").await;
    let subject = unique("subject");
    let bind = UserAttributes { external_id: Some(subject.clone()), ..attributes(&name) };
    assert_eq!(changed(scim.replace_user(id, &bind, &directory()).await.unwrap()).keycloak_id, Some(subject.clone()));
    changed(scim.replace_user(id, &bind, &directory()).await.unwrap());
    // A replacement without one leaves the binding as it is.
    assert_eq!(
        changed(scim.replace_user(id, &attributes(&name), &directory()).await.unwrap()).keycloak_id,
        Some(subject.clone())
    );

    let rebind = UserAttributes { external_id: Some("attacker-subject".to_owned()), ..attributes(&name) };
    assert_eq!(
        invalid(scim.replace_user(id, &rebind, &directory()).await),
        "externalId is immutable once set: this account is already bound to another identity-provider subject."
    );
    assert_eq!(subject_of(db, id).await, Some(subject));
    fixture.log.take();
}

/// An existing privileged account, one with an unreadable role, or one with a local second factor is not bound by the
/// directory; the operator's setting opens the first two, never the third.
async fn a_privileged_or_second_factor_account_is_not_bound(fixture: &Fixture) {
    let db = &fixture.db;
    let privileged = "This account holds a privileged role, so the directory does not bind it to an identity-provider \
                      subject; an administrator does, in Vectispire.";
    // Each is privileged by one flag at least: CISO by many, the champion by approving triage, the auditor by its
    // global scope; `admin` is no role Java reads, and an unreadable role counts as privileged.
    for role in ["CISO", "SECURITY_CHAMPION", "AUDITOR", "admin"] {
        let (id, name) = account(db, "scim-privileged", role).await;
        let bind = UserAttributes { external_id: Some(unique("attacker")), ..attributes(&name) };
        assert_eq!(invalid(fixture.scim().replace_user(id, &bind, &directory()).await), privileged, "{role}");
        assert_eq!(subject_of(db, id).await, None);
        let linked = changed(fixture.provisioning(true).replace_user(id, &bind, &directory()).await.unwrap());
        assert_eq!(linked.keycloak_id, bind.external_id, "{role}: privileged linking allowed");
    }

    let (id, name) = account(db, "scim-totp", "USER").await;
    execute(
        db,
        "update t_user set mfa_enabled = true where id = ?",
        "update t_user set mfa_enabled = true where id = $1",
        &[Bind::Int(id)],
    )
    .await;
    let bind = UserAttributes { external_id: Some(unique("attacker")), ..attributes(&name) };
    for linking in [false, true] {
        assert_eq!(
            invalid(fixture.provisioning(linking).replace_user(id, &bind, &directory()).await),
            "This account has a local second factor, so the directory does not bind it to an identity-provider \
             subject; an administrator does, in Vectispire."
        );
    }
    assert_eq!(subject_of(db, id).await, None);
    fixture.log.take();
}

/// An account the directory creates: its name trimmed and lower-cased, a password nobody knows, no obligation to
/// change it, active unless told otherwise — and the entry naming it.
async fn an_account_is_provisioned(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let name = unique("scim-provisioned");
    let subject = unique("subject-provisioned");
    let request = UserAttributes {
        user_name: Some(format!("  {}  ", name.to_uppercase())),
        display_name: Some("Provisioned Person".to_owned()),
        email: Some("p@example.org".to_owned()),
        external_id: Some(subject.clone()),
        ..UserAttributes::default()
    };
    let view = created(scim.create_user(&request, &directory()).await.unwrap());
    assert_eq!(view.username, name);
    assert_eq!(view.keycloak_id, Some(subject));
    assert_eq!(view.role, "USER");
    assert!(view.is_active && !view.must_change_password && !view.mfa_enabled);
    assert_eq!(view.display_name.as_deref(), Some("Provisioned Person"));
    assert_eq!(view.email.as_deref(), Some("p@example.org"));
    assert_eq!(
        count(db, &format!("select count(*) from t_user where id = {} and must_change_password = false", view.id))
            .await,
        1
    );
    let hash = text(db, &format!("select password from t_user where id = {}", view.id)).await.unwrap();
    assert!(hash.starts_with("$argon2id$"), "a password nobody knows, hashed: {hash}");
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::UserCreated, &name, format!("SCIM provisioned account: {name}"))]
    );

    let inactive = UserAttributes { active: Some(false), ..attributes(&unique("scim-inactive")) };
    assert!(!created(scim.create_user(&inactive, &directory()).await.unwrap()).is_active);

    assert_eq!(invalid(scim.create_user(&UserAttributes::default(), &directory()).await), "A username is required.");
    assert_eq!(
        invalid(scim.create_user(&attributes("not a name"), &directory()).await),
        "Invalid username: 2 to 64 characters, letters, digits, \". _ -\"."
    );
    fixture.log.take();
}

/// A role change from the directory closes the account's sessions, as a deactivation does; a plain replacement keeps
/// them. Each is recorded in its own words.
async fn a_role_change_or_a_deactivation_closes_the_sessions(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (id, name) = account(db, "scim-promoted", "USER").await;
    session(db, id).await;

    changed(scim.replace_user(id, &attributes(&name), &directory()).await.unwrap());
    assert_eq!(sessions(db, id).await, 1);
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::UserUpdated, &name, format!("SCIM updated account: {name}"))]
    );

    let promote = UserAttributes { role: Some("SECURITY_CHAMPION".to_owned()), ..attributes(&name) };
    changed(scim.replace_user(id, &promote, &directory()).await.unwrap());
    assert_eq!(role_of(db, id).await, "SECURITY_CHAMPION");
    assert_eq!(sessions(db, id).await, 0);
    assert_eq!(
        fixture.log.take(),
        vec![entry(
            AuditOperation::UserUpdated,
            &name,
            format!("SCIM changed the role of {name} from USER to SECURITY_CHAMPION and revoked its sessions")
        )]
    );

    session(db, id).await;
    let leave = UserAttributes { active: Some(false), ..attributes(&name) };
    changed(scim.replace_user(id, &leave, &directory()).await.unwrap());
    assert!(!is_active(db, id).await);
    assert_eq!(sessions(db, id).await, 0);
    assert_eq!(
        fixture.log.take(),
        vec![entry(
            AuditOperation::UserUpdated,
            &name,
            format!("SCIM deactivated account and revoked all active sessions for {name}")
        )]
    );
}

/// An absent account is `None` / `Absent` everywhere and its deletion is no error and no entry; a taken userName is
/// `UsernameTaken`, compared after the name is lower-cased.
async fn absent_and_taken(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    assert_eq!(scim.user(ABSENT).await.unwrap(), None);
    assert_eq!(scim.replace_user(ABSENT, &attributes("scim-nobody"), &directory()).await.unwrap(), UserChange::Absent);
    assert_eq!(
        scim.patch_user(ABSENT, Some(&[operation("replace", Some("active"), Some(json!(false)))]), &directory())
            .await
            .unwrap(),
        None
    );
    scim.delete_user(ABSENT, &directory()).await.unwrap();

    let (_, name) = account(db, "scim-taken", "USER").await;
    assert_eq!(
        scim.create_user(&attributes(&name.to_uppercase()), &directory()).await.unwrap(),
        UserCreation::UsernameTaken
    );
    assert!(fixture.log.take().is_empty());
}

/// An `externalId` another account is bound to is refused as a uniqueness conflict, on creation and on a first
/// binding, with nothing written — the unique constraint answered 500 before asmolabs/vectispire#92.
async fn an_external_id_another_account_holds_is_refused(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let subject = unique("subject-dup");
    let first = created(
        scim.create_user(
            &UserAttributes { external_id: Some(subject.clone()), ..attributes(&unique("scim-first")) },
            &directory(),
        )
        .await
        .unwrap(),
    );
    let second = unique("scim-second");
    let again = UserAttributes { external_id: Some(subject.clone()), ..attributes(&second) };
    assert_eq!(scim.create_user(&again, &directory()).await.unwrap(), UserCreation::ExternalIdTaken);
    assert_eq!(count(db, &format!("select count(*) from t_user where username = '{second}'")).await, 0);

    let (unbound, name) = account(db, "scim-unbound", "USER").await;
    let bind = UserAttributes {
        external_id: Some(subject.clone()),
        display_name: Some("Not Written".to_owned()),
        ..attributes(&name)
    };
    assert_eq!(scim.replace_user(unbound, &bind, &directory()).await.unwrap(), UserChange::ExternalIdTaken);
    assert_eq!(subject_of(db, unbound).await, None);
    assert_eq!(display_name_of(db, unbound).await, None);
    // The account bound to it may name it again.
    let own = UserAttributes { external_id: Some(subject), ..attributes(&first.username) };
    changed(scim.replace_user(first.id, &own, &directory()).await.unwrap());
    fixture.log.take();
}

/// An unsupported filter is `invalidFilter`, never the whole list; `userName eq` and `externalId eq` find their
/// account — any case of attribute and operator — an absent one finds none, and no filter lists every account.
async fn filters_answer_or_refuse(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (_, filtered) = account(db, "scim-filtered", "USER").await;
    account(db, "scim-other", "USER").await;
    let bound = created(
        scim.create_user(
            &UserAttributes {
                external_id: Some("subject \"quoted\"".to_owned()),
                ..attributes(&unique("scim-bound-filter"))
            },
            &directory(),
        )
        .await
        .unwrap(),
    );

    for filter in [
        "displayName eq \"Filter Person\"",
        "userName eq \"scim-filtered\" and active eq true",
        "emails[value eq \"filtered@example.org\"]",
        "userName co \"scim\"",
        "userName eq scim-filtered",
        "(userName eq \"scim-filtered\")",
    ] {
        match scim.users(Some(filter), None, None).await {
            Err(refused @ ScimError::InvalidFilter(_)) => {
                assert_eq!(refused.scim_type(), Some("invalidFilter"));
                assert_eq!(
                    refused.to_string(),
                    format!(
                        "Unsupported filter \"{filter}\": only userName eq \"…\" and externalId eq \"…\" are evaluated."
                    )
                );
            }
            other => panic!("{filter}: expected invalidFilter, got {other:?}"),
        }
    }

    for filter in [format!("userName eq \"{filtered}\""), format!("USERNAME EQ \"{}\"", filtered.to_uppercase())] {
        let page = scim.users(Some(&filter), None, None).await.unwrap();
        assert_eq!(page.total_results, 1, "{filter}");
        assert_eq!(page.resources[0].username, filtered);
    }
    let page = scim.users(Some("externalId eq \"subject \\\"quoted\\\"\""), None, None).await.unwrap();
    assert_eq!((page.total_results, page.resources[0].id), (1, bound.id));
    assert_eq!(scim.users(Some("userName eq \"nobody-here\""), None, None).await.unwrap().total_results, 0);
    assert_eq!(scim.users(Some("externalId eq \"nobody-here\""), None, None).await.unwrap().total_results, 0);

    let accounts = usize::try_from(count(db, "select count(*) from t_user").await).unwrap();
    for filter in [None, Some("  ")] {
        assert_eq!(scim.users(filter, None, None).await.unwrap().total_results, accounts);
    }
    fixture.log.take();
}

/// Users: asked nothing, every account by username; asked a page, that list cut; a filter pages too.
async fn users_are_paged(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    for _ in 0..4 {
        account(db, "scim-pager", "USER").await;
    }
    let every = scim.users(None, None, None).await.unwrap();
    let accounts = usize::try_from(count(db, "select count(*) from t_user").await).unwrap();
    assert_eq!((every.total_results, every.resources.len(), every.start_index), (accounts, accounts, 1));
    let names: Vec<String> = every.resources.iter().map(|user| user.username.clone()).collect();

    let mut paged = Vec::new();
    for start in (1..=accounts).step_by(2) {
        let start = i32::try_from(start).unwrap();
        let page = scim.users(None, Some(start), Some(2)).await.unwrap();
        assert_eq!((page.total_results, page.start_index), (accounts, start));
        paged.extend(page.resources.into_iter().map(|user| user.username));
    }
    assert_eq!(paged, names);

    let one = format!("userName eq \"{}\"", names[1]);
    let filtered = scim.users(Some(&one), Some(1), Some(5)).await.unwrap();
    assert_eq!((filtered.total_results, filtered.resources.len()), (1, 1));
    let past = scim.users(Some(&one), Some(2), Some(5)).await.unwrap();
    assert_eq!((past.total_results, past.resources.len(), past.start_index), (1, 0, 2));
    let none = scim.users(None, Some(0), Some(-1)).await.unwrap();
    assert_eq!((none.total_results, none.resources.len(), none.start_index), (accounts, 0, 1));
}

/// A deletion takes the account, its sessions and what names it; deleting it again is no error and no entry.
async fn an_account_is_deleted_with_its_rows(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (id, name) = account(db, "scim-deleted", "USER").await;
    session(db, id).await;
    let squad = team(db, &unique("Squad")).await;
    member(db, squad, id, "manual").await;

    scim.delete_user(id, &directory()).await.unwrap();
    assert!(!exists(db, id).await);
    assert_eq!(sessions(db, id).await, 0);
    assert!(members(db, squad).await.is_empty());
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::UserDeleted, &name, format!("SCIM deleted account: {name}"))]
    );

    scim.delete_user(id, &directory()).await.unwrap();
    assert!(fixture.log.take().is_empty());
}

/// An account read by id is the row, every column a view carries.
async fn an_account_is_read(fixture: &Fixture) {
    let db = &fixture.db;
    let (id, name) = account(db, "scim-read", "SECURITY_CHAMPION").await;
    let view = fixture.scim().user(id).await.unwrap().unwrap();
    assert_eq!((view.id, view.username.as_str(), view.role.as_str()), (id, name.as_str(), "SECURITY_CHAMPION"));
    assert!(view.is_active && !view.must_change_password && view.keycloak_id.is_none());
}

// ── ScimGroupsRoutesTest, ScimPagingRoutesTest ───────────────────────────────────────────────────────────────────────

/// A group is read with its members — named by username — and listed; an absent one is `None`.
async fn groups_are_read(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (user, name) = account(db, "scim-member", "USER").await;
    let id = team(db, &unique("Platform")).await;
    member(db, id, user, "scim").await;

    let group = scim.group(id).await.unwrap().unwrap();
    assert_eq!((group.id, group.members.len()), (id, 1));
    assert_eq!((group.members[0].user_id, group.members[0].display.as_str()), (user, name.as_str()));
    let listed = scim.groups(None, None).await.unwrap();
    assert_eq!(listed.resources.iter().find(|group| group.id == id).unwrap().members, group.members);
    assert_eq!(scim.group(id + 1000).await.unwrap(), None);
}

/// A group is created with its members, marked as the directory's; a name taken in another case is `NameTaken`, a
/// blank one or one past the column a 400; an entry naming no account is skipped, a repeated one stored once.
async fn a_group_is_created(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (alice, alice_name) = account(db, "scim-alice", "USER").await;
    let (bob, _) = account(db, "scim-bob", "USER").await;
    let name = unique("Payments");
    let values = [
        Some(alice_name.to_uppercase()),
        Some(format!(" {bob} ")),
        Some(alice.to_string()),
        Some("9000000".to_owned()),
        Some("nobody-at-all".to_owned()),
        None,
        Some("  ".to_owned()),
    ];
    let group =
        group_created(scim.create_group(Some(&format!("  {name}  ")), Some(&values), &directory()).await.unwrap());
    assert_eq!(group.name, name);
    let mut expected = vec![alice, bob];
    expected.sort_unstable();
    assert_eq!(member_ids(&group), expected);
    assert_eq!(members(db, group.id).await, expected.iter().map(|id| format!("{id}:scim")).collect::<Vec<_>>());
    assert_eq!(
        text(db, &format!("select description from t_team where id = {}", group.id)).await.as_deref(),
        Some("Created via SCIM")
    );
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamUpdated, &name, format!("SCIM created team: {name}"))]
    );

    assert_eq!(
        scim.create_group(Some(&name.to_lowercase()), None, &directory()).await.unwrap(),
        GroupCreation::NameTaken
    );
    assert_eq!(invalid(scim.create_group(Some(" "), None, &directory()).await), "Group displayName cannot be blank.");
    assert_eq!(invalid(scim.create_group(None, None, &directory()).await), "Group displayName cannot be blank.");
    assert_eq!(
        invalid(scim.create_group(Some(&"g".repeat(101)), None, &directory()).await),
        "The SCIM attribute displayName is longer than 100 characters."
    );
    assert!(fixture.log.take().is_empty());
}

/// A replacement renames the group — read back from the row — and replaces its whole membership, every member the
/// directory's; a blank name is no rename; an absent group is `Absent`.
async fn a_group_is_replaced(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (leaving, _) = account(db, "scim-leaving", "USER").await;
    let (joining, _) = account(db, "scim-joining", "USER").await;
    let (staying, _) = account(db, "scim-staying-by-hand", "USER").await;
    let id = team(db, &unique("Platform")).await;
    member(db, id, leaving, "scim").await;
    member(db, id, staying, "manual").await;
    let renamed = unique("Platform Engineering");

    let values = [Some(joining.to_string()), Some(staying.to_string())];
    let group = group_changed(scim.replace_group(id, Some(&renamed), Some(&values), &directory()).await.unwrap());
    assert_eq!(group.name, renamed);
    assert_eq!(team_name(db, id).await, renamed);
    let mut expected = vec![format!("{joining}:scim"), format!("{staying}:scim")];
    expected.sort_unstable_by_key(|row| row.split(':').next().unwrap().parse::<i64>().unwrap());
    assert_eq!(members(db, id).await, expected, "the whole membership, the directory's");
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamUpdated, &renamed, format!("SCIM updated team: {renamed}"))]
    );

    for blank in [None, Some(" "), Some("\u{2003}")] {
        let kept = group_changed(scim.replace_group(id, blank, None, &directory()).await.unwrap());
        assert_eq!(kept.name, renamed);
        assert!(kept.members.is_empty(), "no members listed is nobody");
    }
    assert_eq!(scim.replace_group(id + 1000, Some("Nobody"), None, &directory()).await.unwrap(), GroupChange::Absent);
    fixture.log.take();
}

/// A rename to a name another group holds is `NameTaken`, by PUT or PATCH in either form, and changes nothing — the
/// membership change beside it included, and no entry.
async fn a_rename_to_a_taken_name_is_refused(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (staying, _) = account(db, "scim-staying", "USER").await;
    let platform = unique("Platform");
    let payments = unique("Payments");
    let id = team(db, &platform).await;
    team(db, &payments).await;
    member(db, id, staying, "scim").await;

    assert_eq!(
        scim.replace_group(id, Some(&payments.to_lowercase()), Some(&[]), &directory()).await.unwrap(),
        GroupChange::NameTaken
    );
    for rename in [
        operation("replace", Some("displayName"), Some(json!(payments))),
        operation("Replace", None, Some(json!({ "displayName": payments.to_uppercase() }))),
    ] {
        let outcome = scim
            .patch_group(id, Some(&[operation("remove", Some("members"), None), rename]), &directory())
            .await
            .unwrap();
        assert_eq!(outcome, GroupChange::NameTaken);
    }
    assert_eq!(team_name(db, id).await, platform);
    assert_eq!(members(db, id).await, vec![format!("{staying}:scim")]);
    assert!(fixture.log.take().is_empty());
}

/// A PATCH renames a group in either form, and its own name in another case is no conflict.
async fn a_patch_renames_a_group(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let id = team(db, &unique("Platform")).await;
    let renamed = unique("Platform Engineering");

    let group = group_changed(
        scim.patch_group(id, Some(&[operation("replace", Some(" DisplayName "), Some(json!(renamed)))]), &directory())
            .await
            .unwrap(),
    );
    assert_eq!(group.name, renamed);
    assert_eq!(team_name(db, id).await, renamed);
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamUpdated, &renamed, format!("SCIM patched team: {renamed}"))]
    );

    let lower = renamed.to_lowercase();
    let group = group_changed(
        scim.patch_group(id, Some(&[operation("Replace", None, Some(json!({ "displayName": lower })))]), &directory())
            .await
            .unwrap(),
    );
    assert_eq!(group.name, lower);
    assert_eq!(team_name(db, id).await, lower);
    // An add with the path renames too, as Java reads it.
    group_changed(
        scim.patch_group(id, Some(&[operation("add", Some("displayName"), Some(json!(renamed)))]), &directory())
            .await
            .unwrap(),
    );
    assert_eq!(team_name(db, id).await, renamed);
    fixture.log.take();
}

/// A displayName past the column, or not a string, is a 400 on creation, replacement and patch, and nothing is
/// written.
async fn a_display_name_past_the_column_or_not_a_string_is_refused(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let platform = unique("Platform");
    let id = team(db, &platform).await;
    let too_long = "g".repeat(101);
    let past = "The SCIM attribute displayName is longer than 100 characters.";
    assert_eq!(invalid(scim.replace_group(id, Some(&too_long), None, &directory()).await), past);
    assert_eq!(
        invalid(
            scim.patch_group(
                id,
                Some(&[operation("replace", Some("displayName"), Some(json!(too_long)))]),
                &directory()
            )
            .await
        ),
        past
    );
    for value in [Some(json!(42)), Some(Value::Null), None] {
        assert_eq!(
            invalid(
                scim.patch_group(id, Some(&[operation("replace", Some("displayName"), value)]), &directory()).await
            ),
            "Group displayName must be a string."
        );
    }
    assert_eq!(
        invalid(
            scim.patch_group(
                id,
                Some(&[operation("replace", None, Some(json!({ "displayName": null })))]),
                &directory()
            )
            .await
        ),
        "Group displayName must be a string."
    );
    assert_eq!(team_name(db, id).await, platform);
    assert!(fixture.log.take().is_empty());
}

/// A PATCH `replace` of the members replaces them, in either form: the unlisted leave whatever set them, the listed
/// newcomers join as the directory's, a listed member keeps its row and its channel; unknown entries are skipped, an
/// empty list empties the team.
async fn a_patch_replaces_the_members(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (former, _) = account(db, "scim-former", "USER").await;
    let (kept, _) = account(db, "scim-kept-by-hand", "USER").await;
    let (newcomer, newcomer_name) = account(db, "scim-newcomer", "USER").await;
    let name = unique("Payments");
    let id = team(db, &name).await;
    member(db, id, former, "scim").await;
    member(db, id, kept, "manual").await;

    let group = group_changed(
        scim.patch_group(
            id,
            Some(&[operation(
                "replace",
                Some("members"),
                Some(json!([
                    { "value": kept.to_string() },
                    { "value": newcomer_name },
                    { "value": "9000000" },
                    { "value": "nobody-at-all" },
                    // An object names nobody (`asString(null)`); it answered 500 before asmolabs/vectispire#92.
                    { "value": { "nested": true } },
                    { "display": "no value" },
                    "7",
                ])),
            )]),
            &directory(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(group.members.len(), 2);
    let mut expected = [(kept, "manual"), (newcomer, "scim")];
    expected.sort_unstable();
    assert_eq!(members(db, id).await, expected.iter().map(|(id, origin)| format!("{id}:{origin}")).collect::<Vec<_>>());
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamUpdated, &name, format!("SCIM patched team: {name}"))]
    );

    group_changed(
        scim.patch_group(
            id,
            Some(&[operation("Replace", None, Some(json!({ "members": [{ "value": former.to_string() }] })))]),
            &directory(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(members(db, id).await, vec![format!("{former}:scim")]);

    // A replacement, a removal of everybody, a replacement: each written before the next reads.
    let group = group_changed(
        scim.patch_group(
            id,
            Some(&[
                operation("replace", Some("members"), Some(json!([{ "value": newcomer.to_string() }]))),
                operation("remove", Some("members"), None),
                operation("replace", Some("members"), Some(json!([{ "value": former.to_string() }]))),
            ]),
            &directory(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(member_ids(&group), vec![former]);
    assert_eq!(members(db, id).await, vec![format!("{former}:scim")]);

    group_changed(
        scim.patch_group(id, Some(&[operation("replace", Some("members"), Some(json!([])))]), &directory())
            .await
            .unwrap(),
    );
    assert!(members(db, id).await.is_empty());

    // An add naming an id no account holds was a 500 from the foreign key; it is skipped.
    group_changed(
        scim.patch_group(
            id,
            Some(&[operation("add", Some("members"), Some(json!([{ "value": "9000000" }])))]),
            &directory(),
        )
        .await
        .unwrap(),
    );
    assert!(members(db, id).await.is_empty());
    fixture.log.take();
}

/// A member replacement beside a refused rename is rolled back with it, and members that are not a list are a 400.
async fn a_refused_rename_rolls_the_replacement_back(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (staying, _) = account(db, "scim-staying", "USER").await;
    let (newcomer, _) = account(db, "scim-newcomer", "USER").await;
    let platform = unique("Platform");
    let payments = unique("Payments");
    let id = team(db, &platform).await;
    team(db, &payments).await;
    member(db, id, staying, "scim").await;

    let outcome = scim
        .patch_group(
            id,
            Some(&[
                operation("replace", Some("members"), Some(json!([{ "value": newcomer.to_string() }]))),
                operation("replace", Some("displayName"), Some(json!(payments))),
            ]),
            &directory(),
        )
        .await
        .unwrap();
    assert_eq!(outcome, GroupChange::NameTaken);
    let outcome = scim
        .patch_group(
            id,
            Some(&[operation("replace", None, Some(json!({ "displayName": payments.to_lowercase(), "members": [] })))]),
            &directory(),
        )
        .await
        .unwrap();
    assert_eq!(outcome, GroupChange::NameTaken);
    for not_a_list in [
        operation("replace", Some("members"), Some(json!("nobody"))),
        operation("replace", Some("members"), None),
        operation("replace", None, Some(json!({ "members": { "value": "1" } }))),
    ] {
        let refused = scim
            .patch_group(
                id,
                Some(&[
                    operation("add", Some("members"), Some(json!([{ "value": newcomer.to_string() }]))),
                    not_a_list,
                ]),
                &directory(),
            )
            .await;
        assert_eq!(invalid(refused), "Group members must be a list.");
    }
    assert_eq!(team_name(db, id).await, platform);
    assert_eq!(members(db, id).await, vec![format!("{staying}:scim")]);
    assert!(fixture.log.take().is_empty());
}

/// A PATCH adds members — in a list or a value's `members` — and removes one by its path or everybody; an add of a
/// member already in makes the row the directory's, as Java's merge does.
async fn a_patch_adds_and_removes_members(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (kept, _) = account(db, "scim-kept", "USER").await;
    let (added, added_name) = account(db, "scim-added", "USER").await;
    let (by_hand, _) = account(db, "scim-by-hand", "USER").await;
    let name = unique("Security");
    let id = team(db, &name).await;
    member(db, id, kept, "scim").await;
    member(db, id, by_hand, "manual").await;

    let group = group_changed(
        scim.patch_group(
            id,
            Some(&[operation("add", Some("members"), Some(json!([{ "value": added.to_string() }])))]),
            &directory(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(group.members.len(), 3);
    group_changed(
        scim.patch_group(
            id,
            Some(&[operation("ADD", None, Some(json!({ "members": [{ "value": by_hand }] })))]),
            &directory(),
        )
        .await
        .unwrap(),
    );
    assert!(members(db, id).await.contains(&format!("{by_hand}:scim")), "the merge takes the directory's origin");

    let group = group_changed(
        scim.patch_group(
            id,
            Some(&[operation("remove", Some(&format!("members[value eq \"{kept}\"]")), None)]),
            &directory(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(group.members.len(), 2);
    group_changed(
        scim.patch_group(
            id,
            Some(&[operation("remove", Some(&format!("members[value eq \"{}\"]", added_name.to_uppercase())), None)]),
            &directory(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(members(db, id).await, vec![format!("{by_hand}:scim")]);
    // A path that names nobody, or another attribute, removes nobody.
    for path in [Some("members[value eq \"9000000\"]"), Some("Members[value eq \"1\"]"), Some("title"), None] {
        group_changed(scim.patch_group(id, Some(&[operation("remove", path, None)]), &directory()).await.unwrap());
    }
    assert_eq!(members(db, id).await, vec![format!("{by_hand}:scim")]);

    group_changed(
        scim.patch_group(id, Some(&[operation("remove", Some("MEMBERS"), None)]), &directory()).await.unwrap(),
    );
    assert!(members(db, id).await.is_empty());
    let entries = fixture.log.take();
    assert_eq!(entries.len(), 9);
    assert!(
        entries
            .iter()
            .all(|logged| *logged == entry(AuditOperation::TeamUpdated, &name, format!("SCIM patched team: {name}")))
    );
    assert_eq!(
        scim.patch_group(id + 1000, Some(&[operation("remove", Some("members"), None)]), &directory()).await.unwrap(),
        GroupChange::Absent
    );
}

/// A group is deleted with its memberships, its grants and its channel; deleting it again is no error and no entry.
async fn a_group_is_deleted(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (user, _) = account(db, "scim-member", "USER").await;
    let name = unique("Retired");
    let id = team(db, &name).await;
    member(db, id, user, "scim").await;
    execute(
        db,
        "insert into t_team_webhook (team_id, url) values (?, 'https://hooks.example/x')",
        "insert into t_team_webhook (team_id, url) values ($1, 'https://hooks.example/x')",
        &[Bind::Int(id)],
    )
    .await;

    scim.delete_group(id, &directory()).await.unwrap();
    assert_eq!(count(db, &format!("select count(*) from t_team where id = {id}")).await, 0);
    assert!(members(db, id).await.is_empty());
    assert_eq!(count(db, &format!("select count(*) from t_team_webhook where team_id = {id}")).await, 0);
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamUpdated, &name, format!("SCIM deleted team: {name}"))]
    );

    scim.delete_group(id, &directory()).await.unwrap();
    assert!(fixture.log.take().is_empty());
}

/// Groups: asked nothing, every group by id; asked a page, that list cut from `startIndex`; out-of-range values read
/// as the RFC says.
async fn groups_are_paged(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    for name in ["Gamma", "Alpha", "Beta", "Delta", "Epsilon"] {
        team(db, &unique(name)).await;
    }
    let every = scim.groups(None, None).await.unwrap();
    let ids: Vec<i64> = every.resources.iter().map(|group| group.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "by identifier");
    assert_eq!((every.total_results, every.start_index), (ids.len(), 1));

    let second = scim.groups(Some(2), Some(2)).await.unwrap();
    assert_eq!(second.resources, every.resources[1..3].to_vec());
    assert_eq!((second.total_results, second.start_index), (ids.len(), 2));
    let past = scim.groups(Some(9999), Some(2)).await.unwrap();
    assert_eq!((past.resources.len(), past.total_results, past.start_index), (0, ids.len(), 9999));
    let below = scim.groups(Some(-5), Some(1)).await.unwrap();
    assert_eq!((below.resources.len(), below.start_index), (1, 1));
    assert_eq!(scim.groups(None, Some(-1)).await.unwrap().resources.len(), 0);
    assert_eq!(scim.groups(None, Some(100_000)).await.unwrap().resources.len(), ids.len().min(500));
}

// ── one transaction per gesture ──────────────────────────────────────────────────────────────────────────────────────

/// A trigger, set as the server's administrator, refusing what `event` does to the rows of `user_id` in `table`.
fn refuse(fixture: &Fixture, trigger: &str, event: &str, table: &str, row: &str, user_id: i64) {
    match fixture.engine() {
        Engine::MySql => {
            fixture.database.sql(&format!(
                "create trigger {trigger} before {event} on {table} for each row begin \
                 if {row}.user_id = {user_id} then signal sqlstate '45000' set message_text = 'refused by the test'; \
                 end if; end"
            ));
        }
        Engine::PostgreSql => {
            fixture.database.sql(
                "create or replace function vs_rs_refuse() returns trigger language plpgsql as \
                 $$ begin raise exception 'refused by the test'; end $$",
            );
            fixture.database.sql(&format!(
                "create trigger {trigger} before {event} on {table} for each row when ({row}.user_id = {user_id}) \
                 execute function vs_rs_refuse()"
            ));
        }
    }
}

fn allow(fixture: &Fixture, trigger: &str, table: &str) {
    match fixture.engine() {
        Engine::MySql => fixture.database.sql(&format!("drop trigger {trigger}")),
        Engine::PostgreSql => fixture.database.sql(&format!("drop trigger {trigger} on {table}")),
    };
}

/// An account's row and the sessions its change closes commit together: the closing refused, the role change, the
/// deactivation and the deletion are not written either — where Java had saved the row before closing the sessions.
async fn an_account_and_its_sessions_commit_together(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (id, name) = account(db, "scim-atomic", "USER").await;
    session(db, id).await;
    refuse(fixture, "vs_rs_refuse_session", "delete", "t_session", "old", id);

    let promote = UserAttributes {
        role: Some("SECURITY_CHAMPION".to_owned()),
        display_name: Some("Promoted".to_owned()),
        ..attributes(&name)
    };
    failed(scim.replace_user(id, &promote, &directory()).await);
    failed(scim.patch_user(id, Some(&[operation("replace", Some("active"), Some(json!(false)))]), &directory()).await);
    failed(scim.delete_user(id, &directory()).await);
    assert_eq!(role_of(db, id).await, "USER");
    assert_eq!(display_name_of(db, id).await, None);
    assert!(is_active(db, id).await && exists(db, id).await);
    assert_eq!(sessions(db, id).await, 1);
    assert!(fixture.log.take().is_empty(), "a gesture rolled back is not recorded");

    allow(fixture, "vs_rs_refuse_session", "t_session");
    scim.delete_user(id, &directory()).await.unwrap();
    assert!(!exists(db, id).await);
    fixture.log.take();
}

/// A group's rename and its membership commit together: a member's insert refused, the rename and the removal of the
/// others are not written either.
async fn a_group_and_its_members_commit_together(fixture: &Fixture) {
    let db = &fixture.db;
    let scim = fixture.scim();
    let (staying, _) = account(db, "scim-atomic-staying", "USER").await;
    let (refused, _) = account(db, "scim-atomic-refused", "USER").await;
    let platform = unique("Platform");
    let id = team(db, &platform).await;
    member(db, id, staying, "manual").await;
    refuse(fixture, "vs_rs_refuse_member", "insert", "t_team_member", "new", refused);

    let values = [Some(refused.to_string())];
    failed(scim.replace_group(id, Some(&unique("Renamed")), Some(&values), &directory()).await);
    failed(
        scim.patch_group(
            id,
            Some(&[
                operation("replace", Some("displayName"), Some(json!(unique("Renamed")))),
                operation("replace", Some("members"), Some(json!([{ "value": refused.to_string() }]))),
            ]),
            &directory(),
        )
        .await,
    );
    failed(scim.create_group(Some(&unique("Created")), Some(&values), &directory()).await);
    assert_eq!(team_name(db, id).await, platform);
    assert_eq!(members(db, id).await, vec![format!("{staying}:manual")]);
    assert_eq!(count(db, "select count(*) from t_team where name like 'Created-%'").await, 0);
    assert!(fixture.log.take().is_empty());
    allow(fixture, "vs_rs_refuse_member", "t_team_member");
}

// ── the runs ─────────────────────────────────────────────────────────────────────────────────────────────────────────

async fn provisioning(engine: Engine) {
    let fixture = Fixture::start(engine).await;
    a_patch_deactivates_and_closes_the_sessions(&fixture).await;
    administrative_accounts_are_protected(&fixture).await;
    an_attribute_past_its_column_is_refused(&fixture).await;
    only_scoped_roles_are_granted(&fixture).await;
    the_held_role_is_no_grant_and_no_role_no_demotion(&fixture).await;
    an_external_id_is_bound_once(&fixture).await;
    a_privileged_or_second_factor_account_is_not_bound(&fixture).await;
    an_account_is_provisioned(&fixture).await;
    a_role_change_or_a_deactivation_closes_the_sessions(&fixture).await;
    absent_and_taken(&fixture).await;
    an_external_id_another_account_holds_is_refused(&fixture).await;
    filters_answer_or_refuse(&fixture).await;
    users_are_paged(&fixture).await;
    an_account_is_deleted_with_its_rows(&fixture).await;
    an_account_is_read(&fixture).await;
    groups_are_read(&fixture).await;
    a_group_is_created(&fixture).await;
    a_group_is_replaced(&fixture).await;
    a_rename_to_a_taken_name_is_refused(&fixture).await;
    a_patch_renames_a_group(&fixture).await;
    a_display_name_past_the_column_or_not_a_string_is_refused(&fixture).await;
    a_patch_replaces_the_members(&fixture).await;
    a_refused_rename_rolls_the_replacement_back(&fixture).await;
    a_patch_adds_and_removes_members(&fixture).await;
    a_group_is_deleted(&fixture).await;
    groups_are_paged(&fixture).await;
    an_account_and_its_sessions_commit_together(&fixture).await;
    a_group_and_its_members_commit_together(&fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scim_provisioning_on_mysql() {
    provisioning(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scim_provisioning_on_postgresql() {
    provisioning(Engine::PostgreSql).await;
}
