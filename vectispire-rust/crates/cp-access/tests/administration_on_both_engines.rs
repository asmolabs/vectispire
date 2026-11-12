//! The administration services on MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`: every statement of
//! `persistence/administration.rs` and the key list's, then the Java tests that hold them — `GrantTargetsRoutesTest`,
//! `TeamVisibilityTest` (the rows behind each route), `ApiKeyIntegrationRoutesTest`'s issuing and revoking, and the
//! services' own sentences and audit entries, word for word.
//!
//! The targets module's answers (`GrantableTargets`) are a table-reading double here: naming a target is the targets
//! module's, held by its own engine test (`cp-targets/tests/engines.rs`, `access_names_and_finds_what_it_grants`).
//!
//! **Docker is required, and its absence fails the test.**

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

#[path = "accounts_support/mod.rs"]
mod accounts_support;
mod support;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use accounts_support::RawCredentials;
use support::{Bind, HandClock, Migrated, execute};
use time::Duration;
use uuid::Uuid;
use vectispire_cp_access::SqlAccountStore;
use vectispire_cp_access::account_names::{AccountDirectory, AccountNames};
use vectispire_cp_access::account_targets::AccountTargets;
use vectispire_cp_access::accounts::{Audit, AuditOperation, AuditRecord, RequestActor};
use vectispire_cp_access::administration::AdminError;
use vectispire_cp_access::api_key_administration::{ApiKeyAdministration, ApiKeyParts};
use vectispire_cp_access::credentials::{
    Clock, CredentialService, IssuerSees, KeyRequest, ScimToken, SessionPolicy, StoreError,
};
use vectispire_cp_access::teams::{TargetAssignment, TeamAdministration, TeamChannels, TeamParts, WebhookPolicy};
use vectispire_cp_access::visibility::{AccessError, Grant, GrantableTargets, Labels, TargetGrant};
use vectispire_cp_db::{Db, Engine, Mode, ScanTarget, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_outbound::OutboundUrlGuard;
use vectispire_cp_outbound::address::Raw;

/// Well past anything a test creates, and never handed out: the engines do not reuse ids.
const ABSENT: i64 = 987_654_321;

// ── doubles ──────────────────────────────────────────────────────────────────────────────────────────────────────────

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

/// `GrantableTargets` read from the targets' tables: a target exists when its row does, and is named after its kind
/// and id.
struct TableTargets(Db);

impl TableTargets {
    async fn present(&self, table: &str, id: i64) -> Result<bool, AccessError> {
        Ok(count(&self.0, &format!("select count(*) from {table} where id = {id}")).await > 0)
    }

    async fn ids(&self, table: &str) -> Vec<i64> {
        let sql = sqlx::AssertSqlSafe(format!("select id from {table} order by id"));
        match &self.0 {
            Db::MySql(pool) => sqlx::query_scalar(sql).fetch_all(pool).await.unwrap(),
            Db::PostgreSql(pool) => sqlx::query_scalar(sql).fetch_all(pool).await.unwrap(),
        }
    }
}

impl GrantableTargets for TableTargets {
    fn targets_in<'a>(&'a self, _: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<Vec<ScanTarget>, AccessError>> {
        Box::pin(async { Err(AccessError::Port("the administration does not resolve projects".to_owned())) })
    }

    fn named<'a>(&'a self, grants: &'a [Grant]) -> BoxFuture<'a, Result<Vec<TargetGrant>, AccessError>> {
        Box::pin(async move {
            let mut named = Vec::new();
            for grant in grants {
                let table = match grant.kind.as_str() {
                    "repository" => Some("t_repository"),
                    "container" => Some("t_container"),
                    "project" => Some("t_project"),
                    _ => None,
                };
                let exists = match table {
                    Some(table) => self.present(table, grant.id).await?,
                    None => false,
                };
                let name = if exists { format!("{} {}", grant.kind, grant.id) } else { "deleted target".to_owned() };
                named.push(TargetGrant { kind: grant.kind.clone(), id: grant.id, name });
            }
            Ok(named)
        })
    }

    fn project_exists(&self, project_id: i64) -> BoxFuture<'_, Result<bool, AccessError>> {
        Box::pin(async move { self.present("t_project", project_id).await })
    }

    fn exists(&self, target: ScanTarget) -> BoxFuture<'_, Result<bool, AccessError>> {
        Box::pin(async move {
            match target {
                ScanTarget::Repository(id) => self.present("t_repository", id).await,
                ScanTarget::Container(id) => self.present("t_container", id).await,
            }
        })
    }

    fn labels(&self) -> BoxFuture<'_, Result<Labels, AccessError>> {
        Box::pin(async move {
            Ok(Labels {
                repositories: self.ids("t_repository").await.into_iter().map(|id| (id, format!("repo-{id}"))).collect(),
                containers: self.ids("t_container").await.into_iter().map(|id| (id, format!("image-{id}"))).collect(),
            })
        })
    }
}

/// `notification_allow_private_url` as the settings would answer it.
struct Private(bool);

impl WebhookPolicy for Private {
    fn private_destinations_allowed(&self) -> BoxFuture<'_, Result<bool, AccessError>> {
        Box::pin(async move { Ok(self.0) })
    }
}

/// The issuer sees every target that exists — the restriction's own checks are the credentials task's.
struct SeesWhatExists(Db);

impl IssuerSees for SeesWhatExists {
    fn issuer_sees<'a>(&'a self, _: i64, target: ScanTarget) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let (table, id) = match target {
                ScanTarget::Repository(id) => ("t_repository", id),
                ScanTarget::Container(id) => ("t_container", id),
            };
            Ok(count(&self.0, &format!("select count(*) from {table} where id = {id}")).await > 0)
        })
    }
}

/// Resolves every name to one public address, and counts the lookups: an over-long URL must cost none.
fn guard(lookups: &Arc<AtomicUsize>) -> OutboundUrlGuard {
    let lookups = lookups.clone();
    OutboundUrlGuard::with_resolver(
        move |host: &str| {
            lookups.fetch_add(1, Ordering::SeqCst);
            // A literal is itself, as the system resolver reads it; a name is one public address.
            let address = host.parse().unwrap_or_else(|_| "93.184.216.34".parse().unwrap());
            vec![Raw::of(address)]
        },
        Vec::new(),
    )
}

// ── fixture ──────────────────────────────────────────────────────────────────────────────────────────────────────────

type SharedClock = Arc<dyn Clock>;

struct Fixture {
    db: Db,
    log: Log,
    clock: Arc<HandClock>,
    lookups: Arc<AtomicUsize>,
}

impl Fixture {
    fn new(db: &Db) -> Fixture {
        Fixture {
            db: db.clone(),
            log: Log::default(),
            clock: HandClock::at(support::now()),
            lookups: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn shared_clock(&self) -> SharedClock {
        self.clock.clone()
    }

    fn teams(&self, private: bool) -> TeamAdministration<Log, SharedClock> {
        TeamAdministration::new(TeamParts {
            db: self.db.clone(),
            audit: self.log.clone(),
            clock: self.shared_clock(),
            outbound: guard(&self.lookups),
            policy: Arc::new(Private(private)),
            targets: Arc::new(TableTargets(self.db.clone())),
        })
    }

    fn accounts(&self) -> AccountTargets<Log> {
        AccountTargets::new(self.db.clone(), self.log.clone(), Arc::new(TableTargets(self.db.clone())))
    }

    fn keys(&self) -> ApiKeyAdministration<Log, SharedClock> {
        ApiKeyAdministration::new(ApiKeyParts {
            db: self.db.clone(),
            credentials: CredentialService::new(
                self.db.clone(),
                self.shared_clock(),
                SessionPolicy::default(),
                Arc::new(support::AgentsTable(self.db.clone())),
                ScimToken::default(),
            ),
            targets: Arc::new(TableTargets(self.db.clone())),
            issuer_sees: Arc::new(SeesWhatExists(self.db.clone())),
            audit: self.log.clone(),
            clock: self.shared_clock(),
        })
    }
}

fn admin() -> RequestActor {
    RequestActor {
        username: Some("admin".to_owned()),
        ip_address: Some("10.0.0.1".to_owned()),
        user_agent: Some("curl/8".to_owned()),
    }
}

fn entry(operation: AuditOperation, resource: impl Into<String>, description: impl Into<String>) -> AuditRecord {
    let actor = admin();
    AuditRecord {
        operation,
        resource: resource.into(),
        description: description.into(),
        username: actor.username,
        ip_address: actor.ip_address,
        user_agent: actor.user_agent,
        signal: None,
    }
}

async fn count(db: &Db, sql: &str) -> i64 {
    let sql = sqlx::AssertSqlSafe(sql.to_owned());
    match db {
        Db::MySql(pool) => sqlx::query_scalar(sql).fetch_one(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar(sql).fetch_one(pool).await.unwrap(),
    }
}

async fn strings(db: &Db, sql: &str) -> Vec<String> {
    let sql = sqlx::AssertSqlSafe(sql.to_owned());
    match db {
        Db::MySql(pool) => sqlx::query_scalar(sql).fetch_all(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar(sql).fetch_all(pool).await.unwrap(),
    }
}

async fn repository(db: &Db) -> i64 {
    let url = format!("https://forge.example/granted-{}.git", Uuid::new_v4());
    execute(
        db,
        "insert into t_repository (url, branch, tier) values (?, 'main', 'TIER_2_BUSINESS_OPERATIONAL')",
        "insert into t_repository (url, branch, tier) values ($1, 'main', 'TIER_2_BUSINESS_OPERATIONAL')",
        &[Bind::Text(&url)],
    )
    .await;
    count(db, "select max(id) from t_repository").await
}

async fn container(db: &Db) -> i64 {
    let name = format!("team/granted-{}", Uuid::new_v4());
    execute(
        db,
        "insert into t_container (image_name, tag) values (?, 'latest')",
        "insert into t_container (image_name, tag) values ($1, 'latest')",
        &[Bind::Text(&name)],
    )
    .await;
    count(db, "select max(id) from t_container").await
}

async fn project(db: &Db) -> i64 {
    let now = support::now();
    let solution = format!("solution-{}", Uuid::new_v4());
    execute(
        db,
        "insert into t_solution (name, created_at) values (?, ?)",
        "insert into t_solution (name, created_at) values ($1, $2)",
        &[Bind::Text(&solution), Bind::Instant(now)],
    )
    .await;
    let solution = count(db, "select max(id) from t_solution").await;
    execute(
        db,
        "insert into t_project (solution_id, name, created_at) values (?, 'granted', ?)",
        "insert into t_project (solution_id, name, created_at) values ($1, 'granted', $2)",
        &[Bind::Int(solution), Bind::Instant(now)],
    )
    .await;
    count(db, "select max(id) from t_project").await
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", &Uuid::new_v4().simple().to_string()[..12])
}

fn assignment(kind: &str, id: i64) -> Option<TargetAssignment> {
    Some(TargetAssignment { kind: Some(kind.to_owned()), id: Some(id) })
}

fn not_found(result: Result<impl std::fmt::Debug, AdminError>) -> String {
    match result {
        Err(AdminError::NotFound(message)) => message,
        other => panic!("expected a 404, got {other:?}"),
    }
}

fn invalid(result: Result<impl std::fmt::Debug, AdminError>) -> String {
    match result {
        Err(AdminError::InvalidInput(message)) => message,
        other => panic!("expected a 400, got {other:?}"),
    }
}

async fn rows_of(db: &Db, table: &str, column: &str, id: i64) -> Vec<String> {
    let sql = sqlx::AssertSqlSafe(format!(
        "select target_kind, target_id from {table} where {column} = {id} order by target_kind, target_id"
    ));
    let rows: Vec<(String, i64)> = match db {
        Db::MySql(pool) => sqlx::query_as(sql).fetch_all(pool).await.unwrap(),
        Db::PostgreSql(pool) => sqlx::query_as(sql).fetch_all(pool).await.unwrap(),
    };
    rows.into_iter().map(|(kind, id)| format!("{kind}:{id}")).collect()
}

// ── GrantTargetsRoutesTest ───────────────────────────────────────────────────────────────────────────────────────────

/// An account granted a repository or an image that does not exist is a 404, and keeps what it held.
async fn an_account_grant_on_an_absent_target_is_refused(fixture: &Fixture) {
    let db = &fixture.db;
    let account = support::account(db, &unique("grant-absent"), "USER", true, false).await;
    let repository = repository(db).await;
    let accounts = fixture.accounts();
    accounts
        .replace_targets(account, Some(&[assignment("repository", repository)]), &Visibility::everything(), &admin())
        .await
        .unwrap();

    for kind in ["repository", "container"] {
        let refused = accounts
            .replace_targets(
                account,
                Some(&[assignment("repository", repository), assignment(kind, ABSENT)]),
                &Visibility::everything(),
                &admin(),
            )
            .await;
        assert_eq!(not_found(refused), format!("No {kind} with id {ABSENT}."));
    }
    assert_eq!(
        rows_of(db, "t_user_target", "user_id", account).await,
        vec![format!("repository:{repository}")],
        "the replacement is refused whole"
    );
}

/// A team granted a repository or an image that does not exist is a 404, and keeps what it held.
async fn a_team_grant_on_an_absent_target_is_refused(fixture: &Fixture) {
    let db = &fixture.db;
    let teams = fixture.teams(false);
    let team = teams.create(Some(&unique("grant-absent")), None, &admin()).await.unwrap().id;
    let image = container(db).await;
    teams.replace_targets(team, &[assignment("container", image)], &Visibility::everything(), &admin()).await.unwrap();

    for kind in ["repository", "container"] {
        let refused = teams
            .replace_targets(
                team,
                &[assignment("container", image), assignment(kind, ABSENT)],
                &Visibility::everything(),
                &admin(),
            )
            .await;
        assert_eq!(not_found(refused), format!("No {kind} with id {ABSENT}."));
    }
    assert_eq!(rows_of(db, "t_team_target", "team_id", team).await, vec![format!("container:{image}")]);
}

/// A grant already held is kept when its target has gone, so the set stays editable; a new one is not.
async fn a_grant_already_held_is_kept(fixture: &Fixture) {
    let db = &fixture.db;
    let account = support::account(db, &unique("grant-held"), "USER", true, false).await;
    execute(
        db,
        "insert into t_user_target (user_id, target_kind, target_id) values (?, 'repository', ?)",
        "insert into t_user_target (user_id, target_kind, target_id) values ($1, 'repository', $2)",
        &[Bind::Int(account), Bind::Int(ABSENT)],
    )
    .await;
    let teams = fixture.teams(false);
    let team = teams.create(Some(&unique("grant-held")), None, &admin()).await.unwrap().id;
    execute(
        db,
        "insert into t_team_target (team_id, target_kind, target_id) values (?, 'container', ?)",
        "insert into t_team_target (team_id, target_kind, target_id) values ($1, 'container', $2)",
        &[Bind::Int(team), Bind::Int(ABSENT)],
    )
    .await;
    let repository = repository(db).await;
    let accounts = fixture.accounts();

    let kept = accounts
        .replace_targets(
            account,
            Some(&[assignment("repository", ABSENT), assignment("repository", repository)]),
            &Visibility::everything(),
            &admin(),
        )
        .await
        .unwrap();
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0].name, "deleted target", "a grant outliving its target is shown, not hidden");
    assert_eq!(rows_of(db, "t_user_target", "user_id", account).await.len(), 2);
    teams
        .replace_targets(
            team,
            &[assignment("container", ABSENT), assignment("repository", repository)],
            &Visibility::everything(),
            &admin(),
        )
        .await
        .unwrap();
    assert_eq!(rows_of(db, "t_team_target", "team_id", team).await.len(), 2);

    // Held as a repository, not as an image: the pair is the grant.
    let refused = accounts
        .replace_targets(account, Some(&[assignment("container", ABSENT)]), &Visibility::everything(), &admin())
        .await;
    assert_eq!(not_found(refused), format!("No container with id {ABSENT}."));
}

// ── the account's grants ─────────────────────────────────────────────────────────────────────────────────────────────

async fn an_account_s_grants_are_read_replaced_and_audited(fixture: &Fixture) {
    let db = &fixture.db;
    let username = unique("grantee");
    let account = support::account(db, &username, "USER", true, false).await;
    let (repository, image, project) = (repository(db).await, container(db).await, project(db).await);
    let accounts = fixture.accounts();
    fixture.log.take();

    // Absent entries and entries without an id are skipped; the same pair twice is one; the kind is lower-cased.
    let stored = accounts
        .replace_targets(
            account,
            Some(&[
                None,
                Some(TargetAssignment { kind: Some("repository".to_owned()), id: None }),
                assignment("Repository", repository),
                assignment("repository", repository),
                assignment(" PROJECT ", project),
                assignment("container", image),
            ]),
            &Visibility::everything(),
            &admin(),
        )
        .await
        .unwrap();
    let pairs: Vec<(String, i64)> = stored.iter().map(|grant| (grant.kind.clone(), grant.id)).collect();
    assert_eq!(
        pairs,
        vec![("repository".to_owned(), repository), ("project".to_owned(), project), ("container".to_owned(), image)],
        "the answer is the assignments as stored, in the order sent"
    );
    assert_eq!(
        fixture.log.take(),
        vec![entry(
            AuditOperation::UserUpdated,
            account.to_string(),
            format!("Visible targets of {username}: 3 assigned")
        )]
    );
    let listed = accounts.targets(account).await.unwrap();
    assert_eq!(listed.len(), 3);
    assert_eq!(
        listed.iter().map(|grant| grant.kind.as_str()).collect::<Vec<_>>(),
        vec!["container", "project", "repository"]
    );

    // A target the granter does not see is refused as an absent one.
    let hidden = accounts
        .replace_targets(account, Some(&[assignment("repository", repository)]), &Visibility::only([]), &admin())
        .await;
    assert!(hidden.is_ok(), "a grant already held is kept whatever the granter sees");
    let other = repository_other(db).await;
    let hidden = accounts
        .replace_targets(account, Some(&[assignment("repository", other)]), &Visibility::only([]), &admin())
        .await;
    assert_eq!(not_found(hidden), format!("No repository with id {other}."));

    // An unknown kind is a 400 naming it as sent; nothing is written.
    let unknown = accounts
        .replace_targets(account, Some(&[assignment("solution", 1)]), &Visibility::everything(), &admin())
        .await;
    assert_eq!(invalid(unknown), "Unknown target kind \"solution\". Expected: repository, container, project.");
    // A missing kind likewise (`AccountInputRoutesTest.anUnknownKindIsRefused`).
    let missing = Some(TargetAssignment { kind: None, id: Some(2) });
    let refused = accounts.replace_targets(account, Some(&[missing]), &Visibility::everything(), &admin()).await;
    assert_eq!(invalid(refused), "Unknown target kind \"null\". Expected: repository, container, project.");
    assert_eq!(rows_of(db, "t_user_target", "user_id", account).await, vec![format!("repository:{repository}")]);
    fixture.log.take();

    // Nothing sent, or a body of null: every grant removed, and said so.
    assert!(accounts.replace_targets(account, None, &Visibility::everything(), &admin()).await.unwrap().is_empty());
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::UserUpdated, account.to_string(), format!("Visible targets of {username}: none"))]
    );
    assert!(rows_of(db, "t_user_target", "user_id", account).await.is_empty());

    assert_eq!(not_found(accounts.targets(ABSENT).await), "Account not found.");
    assert_eq!(
        not_found(accounts.replace_targets(ABSENT, None, &Visibility::everything(), &admin()).await),
        "Account not found."
    );
    assert!(fixture.log.take().is_empty(), "a refusal writes no entry");
}

async fn repository_other(db: &Db) -> i64 {
    repository(db).await
}

// ── teams ────────────────────────────────────────────────────────────────────────────────────────────────────────────

async fn teams_are_created_renamed_listed_and_deleted(fixture: &Fixture) {
    let db = &fixture.db;
    let teams = fixture.teams(false);
    let prefix = unique("Team");
    fixture.log.take();

    let created = teams.create(Some(&format!("  {prefix}-B  ")), Some("  Backend  "), &admin()).await.unwrap();
    assert_eq!(created.name, format!("{prefix}-B"), "trimmed as String.trim trims");
    assert_eq!(created.description.as_deref(), Some("Backend"));
    assert_eq!((created.member_count, created.target_count, created.notified), (0, 0, false));
    assert_eq!(created.created_at, fixture.clock.now());
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamUpdated, created.id.to_string(), format!("Team created: {prefix}-B"))]
    );

    // Unique whatever the casing — the column's constraint would accept both on PostgreSQL.
    let taken = teams.create(Some(&format!("{prefix}-b").to_lowercase()), None, &admin()).await;
    assert_eq!(invalid(taken), format!("A team named \"{}\" already exists.", format!("{prefix}-b").to_lowercase()));
    assert_eq!(invalid(teams.create(Some("   "), None, &admin()).await), "A team name is required.");
    assert_eq!(invalid(teams.create(None, None, &admin()).await), "A team name is required.");
    assert_eq!(
        invalid(teams.create(Some(&"x".repeat(101)), None, &admin()).await),
        "A team name is at most 100 characters."
    );
    assert!(fixture.log.take().is_empty());

    let a = teams.create(Some(&format!("{prefix}-a")), None, &admin()).await.unwrap();
    let c = teams.create(Some(&format!("{prefix}-c")), Some("   "), &admin()).await.unwrap();
    assert_eq!(c.description, None, "a blank description is none");
    fixture.log.take();

    // Renamed: the entry says from what to what; the same name again is "updated", and is written all the same.
    let renamed = teams.rename(c.id, Some(&format!("{prefix}-C")), None, &admin()).await.unwrap();
    assert_eq!(renamed.name, format!("{prefix}-C"));
    let kept = teams.rename(c.id, None, Some("Ops"), &admin()).await.unwrap();
    assert_eq!((kept.name.as_str(), kept.description.as_deref()), (format!("{prefix}-C").as_str(), Some("Ops")));
    assert_eq!(
        fixture.log.take(),
        vec![
            entry(AuditOperation::TeamUpdated, c.id.to_string(), format!("Team {prefix}-c updated → {prefix}-C")),
            entry(AuditOperation::TeamUpdated, c.id.to_string(), format!("Team {prefix}-C updated")),
        ]
    );
    // Its own name in another casing is not taken by another team; another's is.
    teams.rename(c.id, Some(&format!("{prefix}-c")), None, &admin()).await.unwrap();
    assert_eq!(
        invalid(teams.rename(c.id, Some(&format!("{prefix}-A")), None, &admin()).await),
        format!("A team named \"{prefix}-A\" already exists.")
    );
    assert_eq!(count(db, &format!("select count(*) from t_team where id = {} and name = '{prefix}-c'", c.id)).await, 1);

    // The list, by name case-insensitively: a, B, c — where a byte order would put B first.
    let ours = |list: Vec<vectispire_cp_access::teams::TeamView>| -> Vec<String> {
        list.into_iter().map(|team| team.name).filter(|name| name.starts_with(&prefix)).collect()
    };
    assert_eq!(
        ours(teams.list(None).await.unwrap()),
        vec![format!("{prefix}-a"), format!("{prefix}-B"), format!("{prefix}-c")]
    );
    let everything = teams.list(None).await.unwrap();
    let window = vectispire_domain::list_window::ListWindow::new(1, 1).unwrap();
    assert_eq!(teams.list(Some(window)).await.unwrap(), everything[1..2].to_vec());

    // Deleted with its members, grants and channel, explicitly; the entry names the counts.
    let one = support::account(db, &unique("member"), "USER", true, false).await;
    let two = support::account(db, &unique("member"), "USER", true, false).await;
    teams.replace_members(a.id, &[Some(one), Some(two)], &admin()).await.unwrap();
    let repository = repository(db).await;
    teams
        .replace_targets(a.id, &[assignment("repository", repository)], &Visibility::everything(), &admin())
        .await
        .unwrap();
    teams.set_webhook(a.id, Some("https://93.184.216.34/doomed"), &admin()).await.unwrap();
    let listed = teams.list(None).await.unwrap().into_iter().find(|team| team.id == a.id).unwrap();
    assert_eq!((listed.member_count, listed.target_count, listed.notified), (2, 1, true));
    fixture.log.take();

    teams.delete(a.id, &admin()).await.unwrap();
    assert_eq!(
        fixture.log.take(),
        vec![entry(
            AuditOperation::TeamUpdated,
            a.id.to_string(),
            format!("Team deleted: {prefix}-a (2 member(s), 1 target(s))")
        )]
    );
    for table in ["t_team_member", "t_team_target", "t_team_webhook"] {
        assert_eq!(count(db, &format!("select count(*) from {table} where team_id = {}", a.id)).await, 0, "{table}");
    }
    assert_eq!(count(db, &format!("select count(*) from t_team where id = {}", a.id)).await, 0);

    // Every gesture on a team that is not there.
    let actor = admin();
    assert_eq!(not_found(teams.rename(a.id, Some("x"), None, &actor).await), "Team not found.");
    assert_eq!(not_found(teams.delete(a.id, &actor).await), "Team not found.");
    assert_eq!(not_found(teams.members(a.id).await), "Team not found.");
    assert_eq!(not_found(teams.replace_members(a.id, &[], &actor).await), "Team not found.");
    assert_eq!(not_found(teams.targets(a.id).await), "Team not found.");
    assert_eq!(not_found(teams.replace_targets(a.id, &[], &Visibility::everything(), &actor).await), "Team not found.");
    assert_eq!(not_found(teams.set_webhook(a.id, Some(""), &actor).await), "Team not found.");
    assert!(fixture.log.take().is_empty());
}

/// `TeamVisibilityTest`'s membership half: wholesale, nulls and repeats dropped, an unknown account refused.
async fn members_are_replaced_wholesale(fixture: &Fixture) {
    let db = &fixture.db;
    let teams = fixture.teams(false);
    let name = unique("members");
    let team = teams.create(Some(&name), None, &admin()).await.unwrap().id;
    let (one, two) = (
        support::account(db, &unique("member"), "USER", true, false).await,
        support::account(db, &unique("member"), "USER", true, false).await,
    );
    fixture.log.take();

    let stored = teams.replace_members(team, &[Some(two), None, Some(one), Some(two)], &admin()).await.unwrap();
    assert_eq!(stored, vec![two, one], "as sent, without its nulls and repeats");
    assert_eq!(teams.members(team).await.unwrap(), vec![one.min(two), one.max(two)]);
    assert_eq!(
        strings(db, &format!("select origin from t_team_member where team_id = {team}")).await,
        vec!["manual", "manual"]
    );
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamAccessChanged, team.to_string(), format!("Members of {name}: 2"))]
    );

    // Refused rather than skipped, and nothing written.
    let refused = teams.replace_members(team, &[Some(one), Some(987_654), Some(987_655)], &admin()).await;
    assert_eq!(invalid(refused), "No such account(s): [987654, 987655]");
    assert_eq!(teams.members(team).await.unwrap().len(), 2);
    assert!(fixture.log.take().is_empty());

    // An oidc row is rewritten as set by hand, as Java's `deleteByTeamId` then `save` does.
    execute(
        db,
        "update t_team_member set origin = 'oidc' where team_id = ?",
        "update t_team_member set origin = 'oidc' where team_id = $1",
        &[Bind::Int(team)],
    )
    .await;
    teams.replace_members(team, &[Some(one)], &admin()).await.unwrap();
    assert_eq!(strings(db, &format!("select origin from t_team_member where team_id = {team}")).await, vec!["manual"]);

    // Removing the member removes the access: an empty list is a statement.
    assert!(teams.replace_members(team, &[], &admin()).await.unwrap().is_empty());
    assert!(teams.members(team).await.unwrap().is_empty());
    fixture.log.take();
}

/// The targets half: wholesale, and **repeats kept in the answer and the count** as Java keeps them, one row stored.
async fn targets_are_replaced_wholesale(fixture: &Fixture) {
    let db = &fixture.db;
    let teams = fixture.teams(false);
    let name = unique("targets");
    let team = teams.create(Some(&name), None, &admin()).await.unwrap().id;
    let (repository, project) = (repository(db).await, project(db).await);
    fixture.log.take();

    let stored = teams
        .replace_targets(
            team,
            &[
                assignment("repository", repository),
                None,
                assignment("REPOSITORY", repository),
                assignment("project", project),
            ],
            &Visibility::everything(),
            &admin(),
        )
        .await
        .unwrap();
    assert_eq!(stored.len(), 2, "the same target sent twice is one grant (asmolabs/vectispire#87)");
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamAccessChanged, team.to_string(), format!("Targets of {name}: 2"))]
    );
    assert_eq!(
        rows_of(db, "t_team_target", "team_id", team).await,
        vec![format!("project:{project}"), format!("repository:{repository}")],
        "one row per pair"
    );
    assert_eq!(teams.targets(team).await.unwrap().len(), 2);

    assert!(teams.replace_targets(team, &[], &Visibility::everything(), &admin()).await.unwrap().is_empty());
    assert!(rows_of(db, "t_team_target", "team_id", team).await.is_empty());
    fixture.log.take();
}

/// A channel is set, reported as set and never read back; empty removes it; refused before the guard when the column
/// cannot hold it, and by the guard for a private address unless the operator allowed one.
async fn a_channel_is_write_only(fixture: &Fixture) {
    let db = &fixture.db;
    let teams = fixture.teams(false);
    let name = unique("channel");
    let team = teams.create(Some(&name), None, &admin()).await.unwrap().id;
    fixture.log.take();

    let set = teams.set_webhook(team, Some("  https://93.184.216.34/backend  "), &admin()).await.unwrap();
    assert!(set.notified);
    assert_eq!(
        strings(db, &format!("select url from t_team_webhook where team_id = {team}")).await,
        vec!["https://93.184.216.34/backend"],
        "stored as typed, trimmed"
    );
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamAccessChanged, team.to_string(), format!("Webhook set on {name}"))]
    );
    // Set again: one row, the new destination.
    teams.set_webhook(team, Some("https://93.184.216.34/rotated"), &admin()).await.unwrap();
    assert_eq!(
        strings(db, &format!("select url from t_team_webhook where team_id = {team}")).await,
        vec!["https://93.184.216.34/rotated"]
    );
    fixture.log.take();

    // Past the column: refused before the guard resolves anything.
    let before = fixture.lookups.load(Ordering::SeqCst);
    let long = format!("https://hooks.example.org/{}", "a".repeat(480));
    assert_eq!(
        invalid(teams.set_webhook(team, Some(&long), &admin()).await),
        "The webhook URL is longer than 500 characters."
    );
    assert_eq!(fixture.lookups.load(Ordering::SeqCst), before, "no DNS lookup for a URL the column cannot hold");
    // A name is resolved by the guard.
    teams.set_webhook(team, Some("https://hooks.example.org/x"), &admin()).await.unwrap();
    assert!(fixture.lookups.load(Ordering::SeqCst) > before);

    // A private destination: 422 under the public-only policy, accepted once the operator allowed it.
    match teams.set_webhook(team, Some("https://10.0.0.5/hook"), &admin()).await {
        Err(AdminError::UnsafeUrl(message)) => assert!(message.starts_with("team webhook URL: "), "{message}"),
        other => panic!("expected a 422, got {other:?}"),
    }
    assert_eq!(
        strings(db, &format!("select url from t_team_webhook where team_id = {team}")).await,
        vec!["https://hooks.example.org/x"],
        "a refusal writes nothing"
    );
    fixture.log.take();
    let internal = fixture.teams(true);
    assert!(internal.set_webhook(team, Some("https://10.0.0.5/hook"), &admin()).await.unwrap().notified);

    // Whether, never which: the list carries no URL — the view has no field for one.
    let listed = teams.list(None).await.unwrap().into_iter().find(|view| view.id == team).unwrap();
    assert!(listed.notified);
    assert!(!format!("{listed:?}").contains("10.0.0.5"));
    fixture.log.take();

    // Empty removes it rather than storing a blank destination; absent likewise.
    assert!(!teams.set_webhook(team, Some("   "), &admin()).await.unwrap().notified);
    assert_eq!(count(db, &format!("select count(*) from t_team_webhook where team_id = {team}")).await, 0);
    assert_eq!(
        fixture.log.take(),
        vec![entry(AuditOperation::TeamAccessChanged, team.to_string(), format!("Webhook removed from {name}"))]
    );
    assert!(!teams.set_webhook(team, None, &admin()).await.unwrap().notified);
    fixture.log.take();
}

/// `TeamChannels`: what the notification routing reads, in its own transaction.
async fn channels_are_read_for_the_routing(fixture: &Fixture) {
    let db = &fixture.db;
    let teams = fixture.teams(false);
    let repository = repository(db).await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        let team = teams.create(Some(&unique("routed")), None, &admin()).await.unwrap().id;
        teams
            .replace_targets(team, &[assignment("repository", repository)], &Visibility::everything(), &admin())
            .await
            .unwrap();
        ids.push(team);
    }
    teams.set_webhook(ids[2], Some("https://93.184.216.34/third"), &admin()).await.unwrap();
    teams.set_webhook(ids[0], Some("https://93.184.216.34/first"), &admin()).await.unwrap();
    fixture.log.take();

    let mut tx = db.begin(Mode::ReadOnly).await.unwrap();
    assert_eq!(TeamChannels::teams_granted(&mut tx, "repository", repository).await.unwrap(), ids);
    assert!(TeamChannels::teams_granted(&mut tx, "container", repository).await.unwrap().is_empty());
    assert_eq!(TeamChannels::with_channel(&mut tx, &[ids[2], ids[1], ids[0]]).await.unwrap(), vec![ids[0], ids[2]]);
    assert!(TeamChannels::with_channel(&mut tx, &[]).await.unwrap().is_empty());
    assert!(TeamChannels::any_team_has_one(&mut tx).await.unwrap());
    assert_eq!(
        TeamChannels::webhook_url(&mut tx, ids[0]).await.unwrap().as_deref(),
        Some("https://93.184.216.34/first")
    );
    assert_eq!(TeamChannels::webhook_url(&mut tx, ids[1]).await.unwrap(), None);
    tx.commit().await.unwrap();
}

// ── API keys ─────────────────────────────────────────────────────────────────────────────────────────────────────────

async fn keys_are_issued_listed_and_revoked(fixture: &Fixture) {
    let db = &fixture.db;
    let keys = fixture.keys();
    let owner_name = unique("issuer");
    let owner = support::account(db, &owner_name, "ADMIN", true, false).await;
    let repository = repository(db).await;
    fixture.log.take();

    // Issued once: the entry under the key's id, with the scopes as stored; the view names its owner and its target.
    let issued = keys
        .issue(
            owner,
            &KeyRequest {
                name: Some("  ci-pipeline  ".to_owned()),
                scopes: Some(vec![Some("scan".to_owned()), Some("read".to_owned())]),
                target_kind: Some("Repository".to_owned()),
                target_id: Some(repository),
                expires_in_days: Some(1),
            },
            &admin(),
        )
        .await
        .unwrap();
    assert!(issued.secret.expose().starts_with("zsk"));
    let first = issued.key;
    assert_eq!(first.name, "ci-pipeline");
    assert_eq!(first.scopes, vec!["read", "scan"]);
    assert_eq!((first.target_kind.as_deref(), first.target_id), (Some("repository"), Some(repository)));
    assert_eq!(first.target_label, Some(format!("repo-{repository}")));
    assert_eq!(first.owner.as_deref(), Some(owner_name.as_str()));
    assert!(!first.expired);
    assert_eq!(
        fixture.log.take(),
        vec![entry(
            AuditOperation::ApiKeyCreated,
            first.id.as_hyphenated().to_string(),
            "API key issued: ci-pipeline (read,scan)"
        )]
    );

    // Refused in the credentials task's words, and nothing recorded.
    match keys.issue(owner, &KeyRequest { name: Some("  ".to_owned()), ..KeyRequest::default() }, &admin()).await {
        Err(AdminError::InvalidInput(message)) => assert_eq!(message, "A name is required."),
        other => panic!("expected a 400, got {other:?}"),
    }
    let request = KeyRequest {
        name: Some("x".to_owned()),
        target_kind: Some("repository".to_owned()),
        target_id: Some(ABSENT),
        ..KeyRequest::default()
    };
    match keys.issue(owner, &request, &admin()).await {
        Err(AdminError::InvalidApiKey(message)) => {
            assert_eq!(message, format!("No repository {ABSENT} to restrict the key to."))
        }
        other => panic!("expected a 400, got {other:?}"),
    }
    // `ApiKeyIntegrationRoutesTest.issuanceValidatesItsInput` and `theAgentScopeIsRefused`.
    let long = KeyRequest { name: Some("x".repeat(101)), ..KeyRequest::default() };
    match keys.issue(owner, &long, &admin()).await {
        Err(AdminError::InvalidApiKey(message)) => assert_eq!(message, "A key's name is at most 100 characters."),
        other => panic!("expected a 400, got {other:?}"),
    }
    let agent = KeyRequest {
        name: Some("sneaky".to_owned()),
        scopes: Some(vec![Some("agent".to_owned())]),
        ..KeyRequest::default()
    };
    match keys.issue(owner, &agent, &admin()).await {
        Err(AdminError::InvalidApiKey(message)) => {
            assert_eq!(message, "The agent scope is not issued here: declare the agent, which creates its key.");
        }
        other => panic!("expected a 400, got {other:?}"),
    }
    assert!(fixture.log.take().is_empty());

    // Newest first; a day later the first has expired — from its expiry's instant on.
    fixture.clock.advance(Duration::days(1));
    let second = keys
        .issue(owner, &KeyRequest { name: Some("nightly".to_owned()), ..KeyRequest::default() }, &admin())
        .await
        .unwrap()
        .key;
    assert_eq!(second.scopes, vec!["read", "scan", "export"], "the defaults");
    let listed: Vec<_> =
        keys.list(None).await.unwrap().into_iter().filter(|key| key.id == first.id || key.id == second.id).collect();
    assert_eq!(listed.iter().map(|key| key.id).collect::<Vec<_>>(), vec![second.id, first.id]);
    assert!(listed[1].expired, "expired at exactly its expiry");
    assert!(!listed[0].expired);
    assert_eq!(listed[1].owner.as_deref(), Some(owner_name.as_str()));
    let window = vectispire_domain::list_window::ListWindow::new(1, 0).unwrap();
    assert_eq!(keys.list(Some(window)).await.unwrap().len(), 1);

    // A deleted target is said to be deleted.
    execute(
        db,
        "delete from t_repository where id = ?",
        "delete from t_repository where id = $1",
        &[Bind::Int(repository)],
    )
    .await;
    assert_eq!(
        keys.key(first.id).await.unwrap().unwrap().target_label,
        Some(format!("repository {repository} (deleted)"))
    );

    // The owner is named by `key` only while active; the list names every owner.
    execute(
        db,
        "update t_user set is_active = false where id = ?",
        "update t_user set is_active = false where id = $1",
        &[Bind::Int(owner)],
    )
    .await;
    assert_eq!(keys.key(second.id).await.unwrap().unwrap().owner, None);
    assert!(
        keys.list(None)
            .await
            .unwrap()
            .iter()
            .any(|key| key.id == second.id && key.owner.as_deref() == Some(owner_name.as_str()))
    );
    assert_eq!(keys.key(Uuid::new_v4()).await.unwrap(), None);
    execute(
        db,
        "update t_user set is_active = true where id = ?",
        "update t_user set is_active = true where id = $1",
        &[Bind::Int(owner)],
    )
    .await;

    let names = keys.names(&[first.id, second.id, first.id, Uuid::new_v4()]).await.unwrap();
    assert_eq!(names.len(), 2);
    assert_eq!(names.get(&first.id).map(String::as_str), Some("ci-pipeline"));

    // The targets a key may be restricted to, by name.
    let options = keys.targets().await.unwrap();
    let image = container(db).await;
    let options_after = keys.targets().await.unwrap();
    assert_eq!(options_after.containers.len(), options.containers.len() + 1);
    assert_eq!(
        options_after.containers.last().map(|option| (option.id, option.label.clone())),
        Some((image, format!("image-{image}")))
    );
    fixture.log.take();

    // Revoked: the row goes and the entry names the key.
    assert_eq!(not_found(keys.revoke(Uuid::new_v4(), Some(owner), &admin()).await), "Key not found.");
    keys.revoke(first.id, Some(owner), &admin()).await.unwrap();
    assert_eq!(keys.key(first.id).await.unwrap(), None);
    assert_eq!(
        fixture.log.take(),
        vec![entry(
            AuditOperation::ApiKeyDeleted,
            first.id.as_hyphenated().to_string(),
            "API key revoked: ci-pipeline"
        )]
    );

    // A governor's key is revoked by a governor only.
    let governor = support::account(db, &unique("governor"), "SUPERUSER", true, false).await;
    let governed = keys
        .issue(governor, &KeyRequest { name: Some("governance".to_owned()), ..KeyRequest::default() }, &admin())
        .await
        .unwrap()
        .key;
    fixture.log.take();
    let refusal = "Only a platform governor can grant, remove or administer the platform governor role: it is the role that lifts the rules the others act under.";
    assert_eq!(invalid(keys.revoke(governed.id, Some(owner), &admin()).await), refusal);
    assert_eq!(invalid(keys.revoke(governed.id, None, &admin()).await), refusal);
    assert!(keys.key(governed.id).await.unwrap().is_some());
    assert!(fixture.log.take().is_empty());
    keys.revoke(governed.id, Some(governor), &admin()).await.unwrap();
    assert_eq!(keys.key(governed.id).await.unwrap(), None);
    fixture.log.take();
}

// ── names and directory ──────────────────────────────────────────────────────────────────────────────────────────────

async fn accounts_are_named_as_a_document_may_print_them(fixture: &Fixture) {
    let db = &fixture.db;
    let users = SqlAccountStore::new(db.clone(), RawCredentials);
    let names = AccountNames::new(users.clone());
    let directory = AccountDirectory::new(users);
    let (ada, mail, gone) = (unique("ada"), unique("mail"), unique("inactive"));
    let ada_id = support::account(db, &ada, "USER", true, false).await;
    let mail_id = support::account(db, &mail, "USER", true, false).await;
    let gone_id = support::account(db, &gone, "USER", false, false).await;
    execute(
        db,
        "update t_user set display_name = ' Ada Lovelace ' where id = ?",
        "update t_user set display_name = ' Ada Lovelace ' where id = $1",
        &[Bind::Int(ada_id)],
    )
    .await;
    execute(
        db,
        "update t_user set display_name = 'Mail <m@example.org>' where id = ?",
        "update t_user set display_name = 'Mail <m@example.org>' where id = $1",
        &[Bind::Int(mail_id)],
    )
    .await;

    let named = names
        .by_username(&[
            Some(ada.clone()),
            None,
            Some(mail.clone()),
            Some(ada.clone()),
            Some("nobody-at-all".to_owned()),
        ])
        .await
        .unwrap();
    assert_eq!(named.len(), 2);
    assert_eq!(named[&ada].account_id, ada_id);
    assert_eq!(named[&ada].display_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(named[&mail].display_name, None, "an address is not printed");
    assert_eq!(names.by_id(ada_id).await.unwrap().unwrap().display_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(names.by_id(ABSENT).await.unwrap(), None);

    let active = directory.active().await.unwrap();
    assert!(active.iter().any(|user| user.id == ada_id));
    assert!(!active.iter().any(|user| user.id == gone_id), "an inactive account is not a contact");
    let usernames: Vec<&str> = active.iter().map(|user| user.username.as_str()).collect();
    let mut sorted = usernames.clone();
    sorted.sort_unstable();
    assert_eq!(usernames, sorted);
    assert_eq!(directory.by_id(gone_id).await.unwrap().map(|user| user.username), Some(gone));
    assert_eq!(directory.by_id(ABSENT).await.unwrap(), None);
}

// ── the runs ─────────────────────────────────────────────────────────────────────────────────────────────────────────

async fn administration(engine: Engine) {
    let database = Migrated::start(engine).await;
    let fixture = Fixture::new(&database.db);
    an_account_grant_on_an_absent_target_is_refused(&fixture).await;
    a_team_grant_on_an_absent_target_is_refused(&fixture).await;
    a_grant_already_held_is_kept(&fixture).await;
    an_account_s_grants_are_read_replaced_and_audited(&fixture).await;
    teams_are_created_renamed_listed_and_deleted(&fixture).await;
    members_are_replaced_wholesale(&fixture).await;
    targets_are_replaced_wholesale(&fixture).await;
    a_channel_is_write_only(&fixture).await;
    channels_are_read_for_the_routing(&fixture).await;
    keys_are_issued_listed_and_revoked(&fixture).await;
    accounts_are_named_as_a_document_may_print_them(&fixture).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_administration_on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    administration(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_administration_on_postgresql() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    administration(Engine::PostgreSql).await;
}
