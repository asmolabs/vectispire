//! Test harness for `vectispire-cp-agents`: MySQL and PostgreSQL containers, schema migration,
//! component composition, and HTTP router assembly.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sqlx::AssertSqlSafe;
use vectispire_cp_access::credentials::{CredentialService, ScimToken, SessionPolicy, SystemClock as AccessClock};
use vectispire_cp_access::{AccessError, AccessSettings, CallerVisibility, PrincipalGrounds, VisibilityService};
use vectispire_cp_audit::{AuditLog, NoMirror, Record, SystemClock as AuditClock};
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_http::credentials::{BoxFuture, RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::Routes;
use vectispire_cp_http::{Chain, ChainConfig};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_outbox::{Outbox, Registry};
use vectispire_cp_scanning::ports::{BundledRules, IngestionStandIn, NoPlugins};
use vectispire_cp_scanning::{Scanning, ScanningConfig};
use vectispire_cp_targets::{
    AuditSink, Clock, PurgeRegistry, SystemClock as TargetsClock, Targets, TargetsConfig, TargetsForAccess,
};
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::scan_queue::Policy;
use vectispire_domain::secret::Secret;
use vectispire_testkit::docker::Container;

use vectispire_cp_agents::{
    AgentAdministrationService, AgentDirectoryImpl, AgentJobPoller, AgentProtocolService, AgentRowLock, Agents,
    NoAgentPlugins,
};

pub const MYSQL_IMAGE: &str = "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
pub const POSTGRES_IMAGE: &str =
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const PASSWORD: &str = "throwaway-agents-test"; // gitleaks:allow — test fixture
pub const KEY: &str = "cmVmZXJlbmNlLXNjYW5uaW5nLWtleS0zMi1ieXRlcyE="; // gitleaks:allow — test fixture

pub struct Migrated {
    pub engine: Engine,
    pub settings: DbSettings,
    server: Container,
}

impl Migrated {
    pub async fn start(engine: Engine) -> Migrated {
        let server = match engine {
            Engine::MySql => Container::run(
                "agents-mysql",
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
                "agents-postgres",
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
}

fn wait_until_ready(engine: Engine, server: &Container) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let probe = match engine {
            Engine::MySql => Command::new("docker")
                .args([
                    "exec",
                    &server.name,
                    "mysqladmin",
                    "ping",
                    "-h",
                    "127.0.0.1",
                    "-u",
                    "root",
                    &format!("-p{PASSWORD}"),
                ])
                .output(),
            Engine::PostgreSql => {
                Command::new("docker").args(["exec", &server.name, "pg_isready", "-U", "vectispire"]).output()
            }
        };
        if probe.is_ok_and(|output| output.status.success()) {
            return;
        }
        assert!(Instant::now() < deadline, "{engine} container was never ready");
        std::thread::sleep(Duration::from_millis(500));
    }
}

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

pub async fn exec(db: &Db, sql: &str) {
    let statement = AssertSqlSafe(sql.to_owned());
    let result = match db {
        Db::MySql(pool) => sqlx::raw_sql(statement).execute(pool).await.map(drop),
        Db::PostgreSql(pool) => sqlx::raw_sql(statement).execute(pool).await.map(drop),
    };
    result.unwrap_or_else(|error| panic!("{sql}: {error}"));
}

pub async fn count(db: &Db, sql: &str) -> i64 {
    let statement = AssertSqlSafe(sql.to_owned());
    let result = match db {
        Db::MySql(pool) => sqlx::query_scalar::<_, i64>(statement).fetch_one(pool).await,
        Db::PostgreSql(pool) => sqlx::query_scalar::<_, i64>(statement).fetch_one(pool).await,
    };
    result.unwrap_or_else(|error| panic!("{sql}: {error}"))
}

pub async fn text(db: &Db, sql: &str) -> Option<String> {
    let statement = AssertSqlSafe(sql.to_owned());
    let result = match db {
        Db::MySql(pool) => sqlx::query_scalar::<_, Option<String>>(statement).fetch_one(pool).await,
        Db::PostgreSql(pool) => sqlx::query_scalar::<_, Option<String>>(statement).fetch_one(pool).await,
    };
    result.unwrap_or_else(|error| panic!("{sql}: {error}"))
}

pub fn encryption() -> Arc<Encryption> {
    let config = EncryptionConfig { key: Some(Secret::new(KEY)), ..EncryptionConfig::default() };
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(Encryption::new(&config, door).expect("a local key"))
}

pub fn system_clock() -> Arc<dyn Clock> {
    Arc::new(TargetsClock)
}

pub struct Mode(pub &'static str);

impl AccessSettings for Mode {
    fn target_visibility(&self) -> BoxFuture<'_, Result<String, AccessError>> {
        Box::pin(async move { Ok(self.0.to_owned()) })
    }
}

#[derive(Default, Debug)]
pub struct Entries(pub Mutex<Vec<Record>>);

impl AuditSink for Entries {
    fn record(&self, entry: Record) -> BoxFuture<'_, ()> {
        self.0.lock().unwrap().push(entry);
        Box::pin(async {})
    }
}

pub struct Composed {
    pub db: Db,
    pub targets: Arc<Targets>,
    pub scanning: Arc<Scanning>,
    pub agents: Arc<Agents>,
    pub credentials: Arc<CredentialService>,
    pub outbox: Arc<Outbox>,
    pub audit: Arc<AuditLog>,
}

pub fn compose(db: &Db, clock: Arc<dyn Clock>) -> Composed {
    compose_with_ingestor(db, clock, Arc::new(IngestionStandIn::default()))
}

/// The module over a database, with the ingestor a case needs — one that fails, to see what the agent is answered.
pub fn compose_with_ingestor(
    db: &Db,
    clock: Arc<dyn Clock>,
    ingestor: Arc<dyn vectispire_cp_scanning::ports::ScanIngestor>,
) -> Composed {
    let enc = encryption();
    let entries = Arc::new(Entries::default());

    let targets = Arc::new(Targets::new(TargetsConfig {
        db: db.clone(),
        audit: entries.clone(),
        scans: vectispire_cp_scanning::target_scans(db.clone(), clock.clone()),
        backlog: Arc::new(vectispire_cp_issues::TargetBacklogFigures::new(db.clone())),
        purge: PurgeRegistry::stand_ins().with(vectispire_cp_scanning::purge::listeners()),
        encryption: enc.clone(),
        allowed_hosts: GitHostAllowlist::default(),
        clock: Arc::new(TargetsClock),
        visibility: None,
    }));

    let creds = Arc::new(CredentialService::new(
        db.clone(),
        Arc::new(AccessClock),
        SessionPolicy::default(),
        Arc::new(AgentDirectoryImpl::new(db.clone())),
        ScimToken::default(),
    ));

    let claim_lock = Arc::new(AgentRowLock);

    let scanning = Arc::new(Scanning::new(ScanningConfig {
        db: db.clone(),
        clock: clock.clone(),
        targets: targets.clone(),
        encryption: enc.clone(),
        audit: entries.clone(),
        claim_lock,
        rule_sets: Arc::new(BundledRules),
        plugins: Arc::new(NoPlugins),
        ingestor,
        policy: Policy::default(),
        leader_lease: Duration::from_secs(10),
        allowed_hosts: GitHostAllowlist::default(),
        image_platform: None,
        runner: None,
        scanned: Vec::new(),
    }));

    let audit = Arc::new(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(AuditClock), Vec::new()));

    let outbox = Arc::new(Outbox::on_database(
        db.clone(),
        Registry::default(),
        Arc::new(vectispire_cp_maintenance::SystemClock),
    ));

    let catalog = Arc::new(scanning.catalog().clone());
    let dispatcher = Arc::new(scanning.dispatcher().clone());

    let admin = Arc::new(AgentAdministrationService::new(
        db.clone(),
        creds.clone(),
        catalog,
        targets.clone(),
        audit.clone(),
        Vec::new(),
        false,
    ));

    let protocol = Arc::new(AgentProtocolService::new(
        db.clone(),
        dispatcher.clone(),
        audit.clone(),
        outbox.clone(),
        Arc::new(BundledRules),
        Arc::new(NoAgentPlugins),
    ));

    let poller = Arc::new(AgentJobPoller::new(dispatcher, protocol.clone()));
    let agents = Arc::new(Agents::new(admin, protocol, poller));

    Composed { db: db.clone(), targets, scanning, agents, credentials: creds, outbox, audit }
}

pub fn router(
    db: &Db,
    targets: Arc<Targets>,
    scanning: Arc<Scanning>,
    agents: Arc<Agents>,
    credentials: StaticCredentials,
    mode: &'static str,
) -> axum::Router {
    let visibility = VisibilityService::new(db.clone(), Arc::new(Mode(mode)), Arc::new(TargetsForAccess(db.clone())));
    let mut routes = Routes::new(CallerVisibility::new(visibility, Arc::new(PrincipalGrounds)));
    for entry in vectispire_cp_targets::routes(targets)
        .into_iter()
        .chain(vectispire_cp_scanning::routes(scanning))
        .chain(vectispire_cp_agents::routes(agents))
    {
        routes = routes.route(entry);
    }
    let chain =
        Arc::new(Chain::new(ChainConfig::default(), Arc::new(credentials), Arc::new(RecordingAudit::default())));
    routes.build(&chain, None).unwrap()
}

pub async fn clean(db: &Db) {
    for table in
        ["t_audit_log", "t_one_shot_job", "t_finding", "t_scan", "t_agent", "t_repository", "t_container", "t_ssh_key"]
    {
        exec(db, &format!("delete from {table}")).await;
    }
}

pub async fn agent(db: &Db, name: &str, credentials_mode: &str) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    let enabled = match db {
        Db::MySql(_) => "1",
        Db::PostgreSql(_) => "true",
    };
    exec(
        db,
        &format!(
            "insert into t_agent (id, name, kind, credentials_mode, enabled, created_at) values ('{id}', '{name}', 'remote', '{credentials_mode}', {enabled}, '2026-01-01 00:00:00')"
        ),
    )
    .await;
    id
}

pub async fn accept_sealing_key(db: &Db, id: uuid::Uuid, key: &str, generation: i64) -> i64 {
    let id_str = id.as_hyphenated().to_string();
    match db {
        Db::MySql(pool) => {
            let sql = r#"
                update t_agent
                   set sealing_public_key = ?, sealing_key_generation = ?
                 where id = ?
                   and (sealing_key_generation is null
                        or sealing_key_generation < ?
                        or (sealing_key_generation = ? and sealing_public_key = ?))
            "#;
            sqlx::query(sql)
                .bind(key)
                .bind(generation)
                .bind(&id_str)
                .bind(generation)
                .bind(generation)
                .bind(key)
                .execute(pool)
                .await
                .unwrap()
                .rows_affected() as i64
        }
        Db::PostgreSql(pool) => {
            let sql = r#"
                update t_agent
                   set sealing_public_key = $1, sealing_key_generation = $2
                 where id = $3
                   and (sealing_key_generation is null
                        or sealing_key_generation < $4
                        or (sealing_key_generation = $5 and sealing_public_key = $6))
            "#;
            sqlx::query(sql)
                .bind(key)
                .bind(generation)
                .bind(&id_str)
                .bind(generation)
                .bind(generation)
                .bind(key)
                .execute(pool)
                .await
                .unwrap()
                .rows_affected() as i64
        }
    }
}

pub async fn forget_sealing_key(db: &Db, id: uuid::Uuid) -> i64 {
    let id_str = id.as_hyphenated().to_string();
    match db {
        Db::MySql(pool) => {
            sqlx::query("update t_agent set sealing_public_key = null, sealing_key_generation = null where id = ?")
                .bind(&id_str)
                .execute(pool)
                .await
                .unwrap()
                .rows_affected() as i64
        }
        Db::PostgreSql(pool) => {
            sqlx::query("update t_agent set sealing_public_key = null, sealing_key_generation = null where id = $1")
                .bind(&id_str)
                .execute(pool)
                .await
                .unwrap()
                .rows_affected() as i64
        }
    }
}

pub async fn ssh_key(db: &Db, name: &str) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    exec(
        db,
        &format!(
            "insert into t_ssh_key (id, name, private_key, created_at) values ('{id}', '{name}', 'v2:not-read-by-this-test', '2026-01-01 00:00:00')"
        ),
    )
    .await;
    id
}

pub async fn repository(db: &Db, name: &str, key_id: Option<uuid::Uuid>) -> i64 {
    let key_sql = key_id.map_or("null".to_owned(), |id| format!("'{id}'"));
    exec(
        db,
        &format!(
            "insert into t_repository (url, branch, name, ssh_key_id) values ('https://example.invalid/{name}.git', 'main', '{name}', {key_sql})"
        ),
    )
    .await;
    count(db, &format!("select id from t_repository where name = '{name}'")).await
}

pub async fn container(db: &Db, name: &str) -> i64 {
    exec(db, &format!("insert into t_container (image_name, tag) values ('{name}', '1.0')")).await;
    count(db, &format!("select max(id) from t_container where image_name = '{name}'")).await
}

pub async fn scan(db: &Db, repo: Option<i64>, container: Option<i64>, status: &str, attempts: i64) -> i64 {
    let repo_sql = repo.map_or("null".to_owned(), |id| id.to_string());
    let container_sql = container.map_or("null".to_owned(), |id| id.to_string());
    exec(
        db,
        &format!(
            "insert into t_scan (branch, status, created_at, repo_id, container_id, attempts, findings_count, new_issues_count, resolved_issues_count) values ('main', '{status}', '2026-01-01 00:00:00', {repo_sql}, {container_sql}, {attempts}, 0, 0, 0)"
        ),
    )
    .await;
    count(db, "select max(id) from t_scan").await
}

pub async fn attempts(db: &Db, id: i64) -> i64 {
    let cast = match db {
        Db::MySql(_) => "cast(attempts as signed)",
        Db::PostgreSql(_) => "cast(attempts as bigint)",
    };
    count(db, &format!("select {cast} from t_scan where id = {id}")).await
}

pub async fn status(db: &Db, id: i64) -> String {
    text(db, &format!("select status from t_scan where id = {id}")).await.unwrap()
}
