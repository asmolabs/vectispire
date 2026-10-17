//! A throwaway database on each engine, migrated by `vectispire-migrate`, the module composed over it, and the HTTP
//! chain in front of its routes — what the engine and route suites share.
//!
//! The engines are the campaign's, by digest (`Engine.java`, `scripts/upgrade-drill.sh`). Every container is
//! `vs-rs-targets-*`, removed on drop; a missing Docker fails the test (AGENTS.md, "Never skip silently").

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sqlx::AssertSqlSafe;
use vectispire_cp_access::{AccessError, AccessSettings, CallerVisibility, PrincipalGrounds, VisibilityService};
use vectispire_cp_audit::Record;
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_http::credentials::{BoxFuture, RecordingAudit, StaticCredentials};
use vectispire_cp_http::principal::Account;
use vectispire_cp_http::routes::Routes;
use vectispire_cp_http::{Chain, ChainConfig, Grounds, Principal, Restriction, Role};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_targets::{
    AuditSink, IssuesStandIn, PurgeRegistry, ScanningStandIn, SystemClock, Targets, TargetsConfig, TargetsForAccess,
};
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::secret::Secret;
use vectispire_testkit::docker::{Container, docker};

pub const MYSQL_IMAGE: &str = "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
pub const POSTGRES_IMAGE: &str =
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const PASSWORD: &str = "throwaway-targets-test"; // gitleaks:allow — invented, for a container removed after the test
/// An encryption key for the tests' secrets — invented, 32 bytes of base64.
pub const KEY: &str = "dGhyb3dhd2F5LXRhcmdldHMta2V5LTMyLWJ5dGVzISE="; // gitleaks:allow — a test fixture

/// A migrated database.
pub struct Migrated {
    pub engine: Engine,
    pub settings: DbSettings,
    server: Container,
}

impl Migrated {
    pub async fn start(engine: Engine) -> Migrated {
        let server = match engine {
            Engine::MySql => Container::run(
                "targets-mysql",
                &[
                    "-p",
                    "127.0.0.1::3306",
                    "-e",
                    &format!("MYSQL_ROOT_PASSWORD={PASSWORD}"),
                    "-e",
                    "MYSQL_DATABASE=vectispire",
                    "-e",
                    "MYSQL_USER=vectispire",
                    "-e",
                    &format!("MYSQL_PASSWORD={PASSWORD}"),
                    MYSQL_IMAGE,
                    "--default-time-zone=+00:00",
                    "--max-allowed-packet=160M",
                ],
            ),
            Engine::PostgreSql => Container::run(
                "targets-postgres",
                &[
                    "-p",
                    "127.0.0.1::5432",
                    "-e",
                    &format!("POSTGRES_PASSWORD={PASSWORD}"),
                    "-e",
                    "POSTGRES_USER=vectispire",
                    "-e",
                    "POSTGRES_DB=vectispire",
                    POSTGRES_IMAGE,
                ],
            ),
        };
        wait_until_ready(engine, &server);
        let (port, jdbc) = match engine {
            Engine::MySql => (server.host_port("3306/tcp"), "jdbc:mysql"),
            Engine::PostgreSql => (server.host_port("5432/tcp"), "jdbc:postgresql"),
        };
        let settings = DbSettings {
            url: DatabaseUrl::parse(&format!("{jdbc}://127.0.0.1:{port}/vectispire")).unwrap(),
            username: "vectispire".into(),
            password: Secret::new(PASSWORD),
            pool: PoolSettings { max_connections: 8, min_connections: 1, ..PoolSettings::default() },
            ca_pem: None,
        };
        let migrated = Migrated { engine, settings, server };
        let db = migrated.connect().await;
        let database = match &db {
            Db::MySql(pool) => vectispire_migrate::Database::MySql(pool.clone()),
            Db::PostgreSql(pool) => vectispire_migrate::Database::PostgreSql(pool.clone()),
        };
        vectispire_migrate::run(&database, &vectispire_migrate::Options::default()).await.expect("the schema migrates");
        db.close().await;
        migrated
    }

    pub async fn connect(&self) -> Db {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match Db::connect(&self.settings).await {
                Ok(db) => return db,
                Err(failure) => {
                    assert!(Instant::now() < deadline, "{} never answered: {failure}", self.engine);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// A statement as the superuser, inside the container.
    pub fn sql_as_admin(&self, statement: &str) -> String {
        match self.engine {
            Engine::MySql => self.server.exec(&[
                "mysql",
                "-uroot",
                &format!("-p{PASSWORD}"),
                "-N",
                "--default-character-set=utf8mb4",
                "vectispire",
                "-e",
                statement,
            ]),
            Engine::PostgreSql => self.server.exec(&["psql", "-U", "vectispire", "-tAc", statement]),
        }
    }
}

fn wait_until_ready(engine: Engine, server: &Container) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let probe = match engine {
            Engine::MySql => Command::new("docker")
                .args([
                    "exec",
                    &server.name,
                    "mysql",
                    "-uvectispire",
                    &format!("-p{PASSWORD}"),
                    "-h127.0.0.1",
                    "-e",
                    "select 1",
                    "vectispire",
                ])
                .output(),
            Engine::PostgreSql => Command::new("docker")
                .args(["exec", &server.name, "psql", "-h", "127.0.0.1", "-U", "vectispire", "-tAc", "select 1"])
                .output(),
        };
        if probe.is_ok_and(|output| output.status.success()) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{engine} did not start: {}",
            docker(&["logs", "--tail", "40", &server.name])
        );
        std::thread::sleep(Duration::from_millis(500));
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

/// A statement the test writes itself, behind the module's back — seeding what other modules own.
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

pub fn encryption() -> Arc<Encryption> {
    let config = EncryptionConfig { key: Some(Secret::new(KEY)), ..EncryptionConfig::default() };
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(Encryption::new(&config, door).expect("a local key"))
}

/// The module over `db`, its entries recorded, with the stand-ins the binary composes until 2.7 and Phase 3.
pub fn targets(db: &Db, purge: PurgeRegistry) -> (Arc<Targets>, Arc<Entries>) {
    let entries = Arc::new(Entries::default());
    let targets = Targets::new(TargetsConfig {
        db: db.clone(),
        audit: entries.clone(),
        scans: Arc::new(ScanningStandIn),
        backlog: Arc::new(IssuesStandIn),
        purge,
        encryption: encryption(),
        allowed_hosts: GitHostAllowlist::default(),
        clock: Arc::new(SystemClock),
        visibility: None,
    });
    (Arc::new(targets), entries)
}

/// `target_visibility`, as the settings store answers it.
pub struct Mode(pub &'static str);

impl AccessSettings for Mode {
    fn target_visibility(&self) -> BoxFuture<'_, Result<String, AccessError>> {
        Box::pin(async move { Ok(self.0.to_owned()) })
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

/// The module's routes behind the real chain, the visibility resolved by `cp-access` from the principal's grounds.
pub fn router(db: &Db, targets: Arc<Targets>, credentials: StaticCredentials, mode: &'static str) -> axum::Router {
    let visibility = VisibilityService::new(db.clone(), Arc::new(Mode(mode)), Arc::new(TargetsForAccess(db.clone())));
    let mut routes = Routes::new(CallerVisibility::new(visibility, Arc::new(PrincipalGrounds)));
    for entry in vectispire_cp_targets::routes(targets) {
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

/// Every table's rows naming `target`, by table — `TargetRowsFixture.rowsNaming`, for the tables this phase owns.
pub async fn rows_naming(db: &Db, kind: &str, id: i64) -> Vec<(&'static str, i64)> {
    let column = if kind == "repository" { "repo_id" } else { "container_id" };
    let mut found = Vec::new();
    for table in ["t_scan", "t_issue"] {
        found.push((table, count(db, &format!("select count(*) from {table} where {column} = {id}")).await));
    }
    found.push((
        "t_finding",
        count(
            db,
            &format!("select count(*) from t_finding where scan_id in (select id from t_scan where {column} = {id})"),
        )
        .await,
    ));
    found.push((
        "t_user_target",
        count(db, &format!("select count(*) from t_user_target where target_kind = '{kind}' and target_id = {id}"))
            .await,
    ));
    found.push((
        "t_api_key",
        count(db, &format!("select count(*) from t_api_key where target_kind = '{kind}' and target_id = {id}")).await,
    ));
    found
}

pub fn ids(values: &[i64]) -> BTreeSet<i64> {
    values.iter().copied().collect()
}
