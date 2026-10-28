//! A database of its own on each engine, migrated by `vectispire-migrate`, the module composed over it with `targets`,
//! and the HTTP chain in front of its routes — what the engine, route and replay suites share. The database is
//! `vectispire_cp_db::testing`'s: in a throwaway container or on the shared server `VECTISPIRE_TEST_MYSQL_URL` /
//! `VECTISPIRE_TEST_POSTGRES_URL` names; a missing Docker fails the test (AGENTS.md, "Never skip silently").

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sqlx::AssertSqlSafe;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_access::{AccessError, AccessSettings, CallerVisibility, PrincipalGrounds, VisibilityService};
use vectispire_cp_audit::Record;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_http::credentials::{BoxFuture, RecordingAudit, StaticCredentials};
use vectispire_cp_http::principal::Account;
use vectispire_cp_http::routes::Routes;
use vectispire_cp_http::{Chain, ChainConfig, Grounds, Principal, Restriction, Role};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_scanning::ports::{AgentClaimLock, BundledRules, IngestionStandIn, NoPlugins, PortError};
use vectispire_cp_scanning::{Scanning, ScanningConfig};
use vectispire_cp_targets::{
    AuditSink, Clock, IssuesStandIn, PurgeRegistry, SystemClock, Targets, TargetsConfig, TargetsForAccess,
};
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::scan_queue::Policy;
use vectispire_domain::secret::Secret;

#[allow(unused_imports)] // not every suite of the crate reaches a database
pub use vectispire_cp_db::testing::TestDatabase as Migrated;

/// An encryption key for the tests' secrets — invented, 32 bytes of base64; the reference set's (`ScanningReferenceSetTest`).
pub const KEY: &str = "cmVmZXJlbmNlLXNjYW5uaW5nLWtleS0zMi1ieXRlcyE="; // gitleaks:allow — a test fixture

/// What the module asked the audit log to record, in order.
#[derive(Debug, Default)]
pub struct Entries(pub Mutex<Vec<Record>>);

impl Entries {
    pub fn taken(&self) -> Vec<Record> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

impl AuditSink for Entries {
    fn record(&self, entry: Record) -> BoxFuture<'_, ()> {
        self.0.lock().unwrap().push(entry);
        Box::pin(async {})
    }
}

/// A pool that never connects — for a route table, which runs no statement.
pub fn unreachable() -> Db {
    let settings = DbSettings {
        url: DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: Secret::new(""),
        pool: PoolSettings::default(),
        ca_pem: None,
    };
    Db::connect_lazy(&settings).unwrap()
}

/// A statement the test writes itself, behind the module's back.
pub async fn exec(db: &Db, sql: &str) {
    let statement = AssertSqlSafe(sql.to_owned());
    let result = match db {
        Db::MySql(pool) => sqlx::raw_sql(statement).execute(pool).await.map(drop),
        Db::PostgreSql(pool) => sqlx::raw_sql(statement).execute(pool).await.map(drop),
    };
    result.unwrap_or_else(|error| panic!("{sql}: {error}"));
}

/// One number a test reads back.
pub async fn count(db: &Db, sql: &str) -> i64 {
    let statement = AssertSqlSafe(sql.to_owned());
    let result = match db {
        Db::MySql(pool) => sqlx::query_scalar::<_, i64>(statement).fetch_one(pool).await,
        Db::PostgreSql(pool) => sqlx::query_scalar::<_, i64>(statement).fetch_one(pool).await,
    };
    result.unwrap_or_else(|error| panic!("{sql}: {error}"))
}

/// One text a test reads back, `None` for SQL `null`.
pub async fn text(db: &Db, sql: &str) -> Option<String> {
    let statement = AssertSqlSafe(sql.to_owned());
    let result = match db {
        Db::MySql(pool) => sqlx::query_scalar::<_, Option<String>>(statement).fetch_one(pool).await,
        Db::PostgreSql(pool) => sqlx::query_scalar::<_, Option<String>>(statement).fetch_one(pool).await,
    };
    result.unwrap_or_else(|error| panic!("{sql}: {error}"))
}

/// Several numbers a test reads back.
pub async fn numbers(db: &Db, sql: &str) -> Vec<i64> {
    let statement = AssertSqlSafe(sql.to_owned());
    let result = match db {
        Db::MySql(pool) => sqlx::query_scalar::<_, i64>(statement).fetch_all(pool).await,
        Db::PostgreSql(pool) => sqlx::query_scalar::<_, i64>(statement).fetch_all(pool).await,
    };
    result.unwrap_or_else(|error| panic!("{sql}: {error}"))
}

/// An instant as both engines' literals read it: `'2026-08-13 10:00:00.000000'`, UTC.
pub fn literal(at: OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "'{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}'",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        at.nanosecond() / 1_000
    )
}

/// `agents`' row lock, as `AgentRepository.lockForClaim` writes it: the agents module is 2.9's.
#[derive(Debug, Default, Clone, Copy)]
pub struct AgentRowLock;

impl AgentClaimLock for AgentRowLock {
    fn lock_for_claim<'a>(
        &'a self,
        tx: &'a mut Tx,
        agent: Uuid,
        at: OffsetDateTime,
    ) -> BoxFuture<'a, Result<bool, PortError>> {
        Box::pin(async move {
            let id = agent.as_hyphenated().to_string();
            let rows = match tx {
                Tx::MySql(tx) => sqlx::query("update t_agent set last_seen_at = ? where id = ?")
                    .bind(at)
                    .bind(&id)
                    .execute(&mut **tx)
                    .await?
                    .rows_affected(),
                Tx::PostgreSql(tx) => sqlx::query("update t_agent set last_seen_at = $1 where id = $2")
                    .bind(at)
                    .bind(&id)
                    .execute(&mut **tx)
                    .await?
                    .rows_affected(),
            };
            Ok(rows > 0)
        })
    }
}

/// An agent's row: the claim takes it as its lock, so it has to exist.
pub async fn agent(db: &Db, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let enabled = match db {
        Db::MySql(_) => "1",
        Db::PostgreSql(_) => "true",
    };
    exec(
        db,
        &format!(
            "insert into t_agent (id, name, kind, credentials_mode, enabled, created_at) values ('{id}', '{name}',              'remote', 'local', {enabled}, '2026-01-01 00:00:00')"
        ),
    )
    .await;
    id
}

/// A repository row; answers its id.
pub async fn repository(db: &Db, name: &str) -> i64 {
    exec(db, &format!("insert into t_repository (url, branch, name) values ('https://example.invalid/{name}.git', 'main', '{name}')")).await;
    count(db, &format!("select id from t_repository where name = '{name}'")).await
}

/// An image row; answers its id.
pub async fn container(db: &Db, name: &str) -> i64 {
    exec(db, &format!("insert into t_container (image_name, tag) values ('{name}', '1.0')")).await;
    count(db, &format!("select max(id) from t_container where image_name = '{name}'")).await
}

/// A waiting scan, created at `at`; answers its id.
pub async fn scan(db: &Db, repo: Option<i64>, container: Option<i64>, label: Option<&str>, at: OffsetDateTime) -> i64 {
    let label = label.map_or("null".to_owned(), |label| format!("'{label}'"));
    let repo_sql = repo.map_or("null".to_owned(), |id| id.to_string());
    let container_sql = container.map_or("null".to_owned(), |id| id.to_string());
    exec(
        db,
        &format!(
            "insert into t_scan (branch, status, created_at, repo_id, container_id, required_agent_label, attempts,              findings_count, new_issues_count, resolved_issues_count) values ('main', 'pending', {}, {repo_sql},              {container_sql}, {label}, 0, 0, 0, 0)",
            literal(at)
        ),
    )
    .await;
    count(db, "select max(id) from t_scan").await
}

pub fn encryption() -> Arc<Encryption> {
    let config = EncryptionConfig { key: Some(Secret::new(KEY)), ..EncryptionConfig::default() };
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(Encryption::new(&config, door).expect("a local key"))
}

/// A clock a test moves by hand.
#[derive(Debug)]
pub struct MovingClock(pub Mutex<OffsetDateTime>);

impl MovingClock {
    pub fn at(start: OffsetDateTime) -> Arc<MovingClock> {
        Arc::new(MovingClock(Mutex::new(start)))
    }

    pub fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap();
        *now += by;
    }
}

impl Clock for MovingClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

/// `targets` and `scanning` composed as the binary will: targets over the real `TargetScans` and scanning's purge
/// listeners, scanning over `targets`, the agents' row lock, the bundled rules, no plugin, ingestion's stand-in.
pub struct Composed {
    pub targets: Arc<Targets>,
    pub scanning: Arc<Scanning>,
    pub entries: Arc<Entries>,
    pub ingestion: IngestionStandIn,
}

pub fn compose(db: &Db, clock: Arc<dyn Clock>, policy: Policy) -> Composed {
    compose_with(db, clock, policy, GitHostAllowlist::default())
}

pub fn compose_with(db: &Db, clock: Arc<dyn Clock>, policy: Policy, hosts: GitHostAllowlist) -> Composed {
    compose_running(db, clock, policy, hosts, None)
}

/// The same, with a runner for the built-in worker.
pub fn compose_running(
    db: &Db,
    clock: Arc<dyn Clock>,
    policy: Policy,
    hosts: GitHostAllowlist,
    runner: Option<Arc<dyn vectispire_cp_scanning::ports::ScanRunner>>,
) -> Composed {
    let entries = Arc::new(Entries::default());
    let targets = Arc::new(Targets::new(TargetsConfig {
        db: db.clone(),
        audit: entries.clone(),
        scans: vectispire_cp_scanning::target_scans(db.clone(), clock.clone()),
        backlog: Arc::new(IssuesStandIn),
        purge: PurgeRegistry::stand_ins().with(vectispire_cp_scanning::purge::listeners()),
        encryption: encryption(),
        allowed_hosts: hosts.clone(),
        clock: Arc::new(SystemClock),
        visibility: None,
    }));
    let ingestion = IngestionStandIn::default();
    let scanning = Arc::new(Scanning::new(ScanningConfig {
        db: db.clone(),
        clock,
        targets: targets.clone(),
        encryption: encryption(),
        audit: entries.clone(),
        claim_lock: Arc::new(AgentRowLock),
        rule_sets: Arc::new(BundledRules),
        plugins: Arc::new(NoPlugins),
        ingestor: Arc::new(ingestion.clone()),
        policy,
        leader_lease: Duration::from_secs(180),
        allowed_hosts: hosts,
        image_platform: None,
        runner,
        scanned: Vec::new(),
    }));
    Composed { targets, scanning, entries, ingestion }
}

/// The system clock, as the binary has it.
pub fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}
/// `target_visibility`, as the settings store answers it.
pub struct Mode(pub &'static str);

impl AccessSettings for Mode {
    fn target_visibility(&self) -> BoxFuture<'_, Result<String, AccessError>> {
        Box::pin(async move { Ok(self.0.to_owned()) })
    }
}

/// A settings store that does not answer.
pub struct Unanswering;

impl AccessSettings for Unanswering {
    fn target_visibility(&self) -> BoxFuture<'_, Result<String, AccessError>> {
        Box::pin(async { Err(AccessError::Port("the settings did not answer".into())) })
    }
}

/// An account row; answers its id.
pub async fn account(db: &Db, username: &str, role: &str) -> i64 {
    let flag = match db {
        Db::MySql(_) => ("b'1'", "b'0'"),
        Db::PostgreSql(_) => ("true", "false"),
    };
    exec(
        db,
        &format!(
            "insert into t_user (username, role, is_active, created_at, updated_at, must_change_password) values \
             ('{username}', '{role}', {}, '2026-01-01 00:00:00', '2026-01-01 00:00:00', {})",
            flag.0, flag.1
        ),
    )
    .await;
    count(db, &format!("select id from t_user where username = '{username}'")).await
}

/// A principal as the credentials module builds it: the account, its stored role, the credential's restriction.
pub fn principal(username: &str, id: i64, role: Role, restriction: Restriction, key: bool) -> Principal {
    let account = Account { username: username.to_owned(), role: Some(role), must_change_password: false };
    let principal = if key {
        Principal::integration(
            account,
            "key-1",
            vec![
                vectispire_cp_http::ApiKeyScope::Read,
                vectispire_cp_http::ApiKeyScope::Scan,
                vectispire_cp_http::ApiKeyScope::Export,
            ],
        )
    } else {
        Principal::session(account)
    };
    principal.with_grounds(Grounds {
        account_id: Some(id),
        stored_role: Some(role.name().to_owned()),
        restriction,
        actor: Some(if key { format!("{username} (pipeline)") } else { username.to_owned() }),
    })
}

/// The scan routes behind the real chain, the visibility resolved by `cp-access` from the principal's grounds.
pub fn router(db: &Db, scanning: Arc<Scanning>, credentials: StaticCredentials, mode: &'static str) -> axum::Router {
    router_with(db, scanning, credentials, Arc::new(Mode(mode)))
}

/// The same over another settings store — one that fails, for the failure that must not read as "everything".
pub fn router_with(
    db: &Db,
    scanning: Arc<Scanning>,
    credentials: StaticCredentials,
    settings: Arc<dyn AccessSettings>,
) -> axum::Router {
    let visibility = VisibilityService::new(db.clone(), settings, Arc::new(TargetsForAccess(db.clone())));
    let mut routes = Routes::new(CallerVisibility::new(visibility, Arc::new(PrincipalGrounds)));
    for entry in vectispire_cp_scanning::routes(scanning) {
        routes = routes.route(entry);
    }
    let chain =
        Arc::new(Chain::new(ChainConfig::default(), Arc::new(credentials), Arc::new(RecordingAudit::default())));
    routes.build(&chain, None).unwrap()
}

/// `targets`' routes and the scan routes behind one chain — what the binary will serve.
pub fn router_with_targets(
    db: &Db,
    targets: Arc<Targets>,
    scanning: Arc<Scanning>,
    credentials: StaticCredentials,
    mode: &'static str,
) -> axum::Router {
    let visibility = VisibilityService::new(db.clone(), Arc::new(Mode(mode)), Arc::new(TargetsForAccess(db.clone())));
    let mut routes = Routes::new(CallerVisibility::new(visibility, Arc::new(PrincipalGrounds)));
    for entry in vectispire_cp_targets::routes(targets).into_iter().chain(vectispire_cp_scanning::routes(scanning)) {
        routes = routes.route(entry);
    }
    let chain =
        Arc::new(Chain::new(ChainConfig::default(), Arc::new(credentials), Arc::new(RecordingAudit::default())));
    routes.build(&chain, None).unwrap()
}

/// A request through the router, as a peer on the loopback address.
pub async fn send(
    router: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let mut request = http::Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    if body.is_some() {
        request = request.header("Content-Type", "application/json");
    }
    let mut request = request.body(axum::body::Body::from(body.unwrap_or("").to_owned())).unwrap();
    request.extensions_mut().insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}
