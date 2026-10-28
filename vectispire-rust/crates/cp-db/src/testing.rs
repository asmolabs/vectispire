//! Test support, behind the `test-support` feature, which only `[dev-dependencies]` turn on: **a database of its
//! own for each test**, on a throwaway server or on a shared one.
//!
//! - **Without the variables below**, each [`TestDatabase`] starts its own server in a container named `vs-rs-db-*`,
//!   removed when the value is dropped — what every crate's support did by itself before this module, and what
//!   `./check.sh` runs. A missing Docker fails the test (AGENTS.md, "Never skip silently").
//! - **With `VECTISPIRE_TEST_MYSQL_URL` or `VECTISPIRE_TEST_POSTGRES_URL`** — a server URL with no database,
//!   `jdbc:mysql://127.0.0.1:3306`, and an account that may create databases in `…_USER` and `…_PASSWORD`, the
//!   names the Java suite's `VECTISPIRE_TEST_DB_URL` uses — each test creates a database of its own on that server,
//!   `vs_rs_<epoch seconds>_<pid>_<sequence>`, and drops it when the value is dropped. CI's `rust` job runs one
//!   server of each engine as a job service, so the suite pays two starts instead of one per test.
//!
//! **Nothing is shared between two tests but the server.** A table, a row, a sequence, a migration history: each is
//! in the test's own database (MySQL: and a user of the same name, granted that database only, as the image's
//! entrypoint grants `MYSQL_USER` its `MYSQL_DATABASE`). What a test must not do on a shared server is read the
//! server's own tables unfiltered — `pg_stat_activity`, `performance_schema` — which see every test's sessions; the
//! queries that do filter by the test's database.
//!
//! **The server is the campaign's engine, by digest**, here once for every crate ([`MYSQL_IMAGE`],
//! [`POSTGRES_IMAGE`]; `scripts/check-db-pins.py` holds CI's job services to the same). A shared MySQL is given the
//! composition's flags at its first use by a process — a job service takes no command line, as the Java suite's
//! `TestDatabase` says for the same reason: `time_zone` `+00:00`, `max_allowed_packet` 160 MB, and enough
//! connections for the tests running at once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // A test helper fails the test, which is the point.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sqlx::{AssertSqlSafe, Row as _};
use vectispire_domain::secret::Secret;
use vectispire_testkit::docker::{Container, docker};

use crate::{DatabaseUrl, Db, DbSettings, Engine, PoolSettings};

/// `Engine.MYSQL` of the campaign, by digest.
pub const MYSQL_IMAGE: &str = "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
/// `Engine.POSTGRESQL` of the campaign, by digest.
pub const POSTGRES_IMAGE: &str =
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";

/// The application account's password, on a throwaway server and on a shared one alike.
const PASSWORD: &str = "throwaway-test-database"; // gitleaks:allow — invented, for a database removed after the test

/// Every database and user this module creates on a shared server starts with this, and nothing else it touches.
const PREFIX: &str = "vs_rs_";

/// A database left by a process that was killed before dropping it is swept once it is this old.
const STALE: Duration = Duration::from_secs(24 * 60 * 60);

/// The variables naming a shared server, per engine: the URL without a database, then the account.
fn variables(engine: Engine) -> [&'static str; 3] {
    match engine {
        Engine::MySql => ["VECTISPIRE_TEST_MYSQL_URL", "VECTISPIRE_TEST_MYSQL_USER", "VECTISPIRE_TEST_MYSQL_PASSWORD"],
        Engine::PostgreSql => {
            ["VECTISPIRE_TEST_POSTGRES_URL", "VECTISPIRE_TEST_POSTGRES_USER", "VECTISPIRE_TEST_POSTGRES_PASSWORD"]
        }
    }
}

#[derive(Clone)]
struct Account {
    user: String,
    password: String,
}

/// A shared server, as the variables name it.
#[derive(Clone)]
struct Server {
    host: String,
    port: u16,
    admin: Account,
}

/// A database of its own for one test: migrated by `vectispire-migrate` ([`TestDatabase::start`]) or empty
/// ([`TestDatabase::empty`]). Dropping it removes it — the container, or the database on the shared server.
pub struct TestDatabase {
    pub engine: Engine,
    /// The application's account on this database, as the control plane would be configured.
    pub settings: DbSettings,
    /// The server's port, on [`TestDatabase::host`].
    pub port: u16,
    host: String,
    name: String,
    admin: Account,
    backing: Backing,
}

enum Backing {
    Throwaway(Container),
    Shared,
}

impl std::fmt::Debug for TestDatabase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TestDatabase")
            .field("engine", &self.engine)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("name", &self.name)
            .field("shared", &self.is_shared())
            .finish_non_exhaustive()
    }
}

impl TestDatabase {
    /// A database with the schema `vectispire-migrate` builds — the runner its own oracle holds to Flyway.
    pub async fn start(engine: Engine) -> TestDatabase {
        let database = TestDatabase::empty(engine);
        let db = database.connect().await;
        let migrate = match &db {
            Db::MySql(pool) => vectispire_migrate::Database::MySql(pool.clone()),
            Db::PostgreSql(pool) => vectispire_migrate::Database::PostgreSql(pool.clone()),
        };
        let report = vectispire_migrate::run(&migrate, &vectispire_migrate::Options::default())
            .await
            .expect("the schema migrates");
        // A fresh database takes every migration; a few applied would be a database some other test had filled.
        assert!(report.applied.len() > 80, "{engine}: {} migrations applied", report.applied.len());
        db.close().await;
        database
    }

    /// A database with nothing in it, for a test that migrates it itself.
    pub fn empty(engine: Engine) -> TestDatabase {
        match shared(engine) {
            Some(server) => TestDatabase::on_shared(engine, server),
            None => TestDatabase::throwaway(engine),
        }
    }

    /// A pool on it, as the application's account; the first connection is retried for a minute.
    pub async fn connect(&self) -> Db {
        connect_retrying(&self.settings).await
    }

    /// A statement run as the server's administrator on this database — for what a test sets up or breaks behind
    /// the pool's back — and its rows as the command-line clients print them: `mysql -N`'s tab-separated batch lines
    /// (`NULL`, and `\t`, `\n`, `\0`, `\\` escaped), `psql -tA`'s `|`-separated ones (a null empty), trimmed.
    pub fn sql_as_admin(&self, statement: &str) -> String {
        let settings = self.admin_settings();
        blocking(async move {
            let db = connect_retrying(&settings).await;
            let lines = rows_as_text(&db, statement).await;
            db.close().await;
            lines
        })
    }

    /// The application's account.
    pub fn username(&self) -> &str {
        &self.settings.username
    }

    /// The application's password: the throwaway servers' own, or on a shared PostgreSQL the administrator's.
    pub fn password(&self) -> &str {
        self.settings.password.expose()
    }

    /// The server's host, as this process reaches it.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The database's name on its server.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the database is on a shared server rather than in a container of its own.
    pub fn is_shared(&self) -> bool {
        matches!(self.backing, Backing::Shared)
    }

    /// The throwaway server's container, when there is one.
    pub fn container(&self) -> Option<&Container> {
        match &self.backing {
            Backing::Throwaway(container) => Some(container),
            Backing::Shared => None,
        }
    }

    /// The URL a JDBC driver connects with — without TLS, as the throwaway servers serve it.
    pub fn jdbc_url(&self) -> String {
        let TestDatabase { host, port, name, .. } = self;
        match self.engine {
            Engine::MySql => format!("jdbc:mysql://{host}:{port}/{name}?allowPublicKeyRetrieval=true&useSSL=false"),
            Engine::PostgreSql => format!("jdbc:postgresql://{host}:{port}/{name}"),
        }
    }

    /// The URL sqlx connects with, the application's account in it.
    pub fn url(&self) -> String {
        let TestDatabase { host, port, name, .. } = self;
        // The account percent-encoded where a URL would read it otherwise: a shared server's password is the
        // operator's choice.
        let encode = |text: &str| {
            text.chars()
                .map(|c| match c {
                    '%' | '@' | ':' | '/' | '?' | '#' => format!("%{:02X}", u32::from(c)),
                    other => other.to_string(),
                })
                .collect::<String>()
        };
        let (user, password) = (encode(self.username()), encode(self.password()));
        match self.engine {
            Engine::MySql => format!("mysql://{user}:{password}@{host}:{port}/{name}"),
            Engine::PostgreSql => format!("postgres://{user}:{password}@{host}:{port}/{name}"),
        }
    }

    fn admin_settings(&self) -> DbSettings {
        settings(self.engine, &self.host, self.port, &self.name, &self.admin, 2)
    }

    fn throwaway(engine: Engine) -> TestDatabase {
        let server = match engine {
            Engine::MySql => Container::run(
                "db-mysql",
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
                    // The shipped composition's server flags (docker-compose.yml).
                    "--default-time-zone=+00:00",
                    "--max-allowed-packet=160M",
                ],
            ),
            Engine::PostgreSql => Container::run(
                "db-postgres",
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
        let port = server.host_port(match engine {
            Engine::MySql => "3306/tcp",
            Engine::PostgreSql => "5432/tcp",
        });
        let application = Account { user: "vectispire".into(), password: PASSWORD.into() };
        // The image's own superuser: MySQL's root, PostgreSQL's POSTGRES_USER — the application's account there.
        let admin = Account {
            user: match engine {
                Engine::MySql => "root".into(),
                Engine::PostgreSql => "vectispire".into(),
            },
            password: PASSWORD.into(),
        };
        let host = "127.0.0.1".to_owned();
        let name = "vectispire".to_owned();
        TestDatabase {
            engine,
            settings: settings(engine, &host, port, &name, &application, 8),
            port,
            host,
            name,
            admin,
            backing: Backing::Throwaway(server),
        }
    }

    fn on_shared(engine: Engine, server: Server) -> TestDatabase {
        static SEQUENCE: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "{PREFIX}{}_{}_{}",
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs()),
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let statements = match engine {
            // `_` is a wildcard in a grant's database name: escaped, as the image's entrypoint escapes it.
            Engine::MySql => vec![
                format!("create database `{name}`"),
                format!("create user '{name}'@'%' identified by '{PASSWORD}'"),
                format!("grant all on `{}`.* to '{name}'@'%'", name.replace('_', "\\_")),
            ],
            Engine::PostgreSql => vec![format!("create database \"{name}\"")],
        };
        let admin = server.admin.clone();
        let maintenance = settings(engine, &server.host, server.port, maintenance_database(engine), &admin, 2);
        blocking(async move {
            let db = connect_retrying(&maintenance).await;
            for statement in &statements {
                execute(&db, statement).await;
            }
            db.close().await;
        });
        // PostgreSQL's application account is the administrator, as POSTGRES_USER is both on a throwaway server.
        let application = match engine {
            Engine::MySql => Account { user: name.clone(), password: PASSWORD.into() },
            Engine::PostgreSql => admin.clone(),
        };
        TestDatabase {
            engine,
            settings: settings(engine, &server.host, server.port, &name, &application, 8),
            port: server.port,
            host: server.host,
            name,
            admin,
            backing: Backing::Shared,
        }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        if !self.is_shared() {
            return; // the container's own drop removes it
        }
        let maintenance =
            settings(self.engine, &self.host, self.port, maintenance_database(self.engine), &self.admin, 2);
        let (engine, name) = (self.engine, self.name.clone());
        // Never a panic here — it would abort a test already unwinding; a database left behind is swept a day later.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            blocking(async move {
                if let Ok(db) = Db::connect(&maintenance).await {
                    drop_database(&db, engine, &name).await;
                    db.close().await;
                }
            });
        }));
    }
}

/// The database an administrator connects to when it is not working in a test's own.
fn maintenance_database(engine: Engine) -> &'static str {
    match engine {
        Engine::MySql => "mysql",
        Engine::PostgreSql => "postgres",
    }
}

fn settings(engine: Engine, host: &str, port: u16, database: &str, account: &Account, pool: u32) -> DbSettings {
    let scheme = match engine {
        Engine::MySql => "mysql",
        Engine::PostgreSql => "postgresql",
    };
    DbSettings {
        url: DatabaseUrl::parse(&format!("jdbc:{scheme}://{host}:{port}/{database}")).unwrap(),
        username: account.user.clone(),
        password: Secret::new(account.password.clone()),
        pool: PoolSettings { max_connections: pool, min_connections: 1, ..PoolSettings::default() },
        ca_pem: None,
    }
}

/// The shared server of `engine`, prepared once per process, or `None` when no variable names one.
fn shared(engine: Engine) -> Option<Server> {
    static SERVERS: OnceLock<Mutex<HashMap<Engine, Option<Server>>>> = OnceLock::new();
    let mut servers = SERVERS.get_or_init(Default::default).lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    servers
        .entry(engine)
        .or_insert_with(|| {
            let server = from_environment(engine)?;
            prepare(engine, &server);
            Some(server)
        })
        .clone()
}

fn from_environment(engine: Engine) -> Option<Server> {
    let [url_variable, user_variable, password_variable] = variables(engine);
    let url = std::env::var(url_variable).ok().filter(|url| !url.is_empty())?;
    let required = |variable: &str| {
        std::env::var(variable).unwrap_or_else(|_| panic!("{url_variable} names a server, and {variable} is not set"))
    };
    let admin = Account { user: required(user_variable), password: required(password_variable) };
    let authority = url
        .strip_prefix(match engine {
            Engine::MySql => "jdbc:mysql://",
            Engine::PostgreSql => "jdbc:postgresql://",
        })
        .filter(|authority| !authority.is_empty() && !authority.contains(['/', '?', '@']))
        .unwrap_or_else(|| {
            panic!(
                "{url_variable} is {url}: a server URL with no database, jdbc:{engine}://host:port",
                engine = scheme(engine)
            )
        });
    let parsed = DatabaseUrl::parse(&format!("jdbc:{}://{authority}/{PREFIX}", scheme(engine)))
        .unwrap_or_else(|error| panic!("{url_variable}: {error}"));
    Some(Server { host: parsed.host, port: parsed.port, admin })
}

fn scheme(engine: Engine) -> &'static str {
    match engine {
        Engine::MySql => "mysql",
        Engine::PostgreSql => "postgresql",
    }
}

/// The composition's flags on a shared MySQL, and the sweep of what a killed process left on either engine.
fn prepare(engine: Engine, server: &Server) {
    let maintenance = settings(engine, &server.host, server.port, maintenance_database(engine), &server.admin, 2);
    blocking(async move {
        let db = connect_retrying(&maintenance).await;
        if engine == Engine::MySql {
            for statement in [
                "set global time_zone = '+00:00'",
                "set global max_allowed_packet = 167772160",
                "set global max_connections = 1000",
            ] {
                execute(&db, statement).await;
            }
        }
        let listing = match engine {
            Engine::MySql => format!(
                "select schema_name from information_schema.schemata where schema_name like '{}%' \
                 union select user from mysql.user where user like '{}%'",
                PREFIX.replace('_', "\\_"),
                PREFIX.replace('_', "\\_")
            ),
            Engine::PostgreSql => {
                format!("select datname from pg_database where datname like '{}%'", PREFIX.replace('_', "\\_"))
            }
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs());
        for name in rows_as_text(&db, &listing).await.lines() {
            let created = name.strip_prefix(PREFIX).and_then(|rest| rest.split('_').next()?.parse::<u64>().ok());
            if created.is_some_and(|created| now.saturating_sub(created) > STALE.as_secs()) {
                drop_database(&db, engine, name).await;
            }
        }
        db.close().await;
    });
}

async fn drop_database(db: &Db, engine: Engine, name: &str) {
    match engine {
        Engine::MySql => {
            // A session the test left open would hold the database's metadata lock and stall the drop.
            let sessions = rows_as_text(
                db,
                &format!("select id from performance_schema.processlist where user = '{name}' or db = '{name}'"),
            )
            .await;
            for id in sessions.lines() {
                let _ = sqlx_execute(db, &format!("kill {id}")).await;
            }
            let _ = sqlx_execute(db, &format!("drop database if exists `{name}`")).await;
            let _ = sqlx_execute(db, &format!("drop user if exists '{name}'@'%'")).await;
        }
        Engine::PostgreSql => {
            let _ = sqlx_execute(db, &format!("drop database if exists \"{name}\" with (force)")).await;
        }
    }
}

async fn execute(db: &Db, statement: &str) {
    if let Err(error) = sqlx_execute(db, statement).await {
        panic!("{statement}: {error}");
    }
}

async fn sqlx_execute(db: &Db, statement: &str) -> Result<(), sqlx::Error> {
    let statement = AssertSqlSafe(statement.to_owned());
    match db {
        Db::MySql(pool) => sqlx::raw_sql(statement).execute(pool).await.map(drop),
        Db::PostgreSql(pool) => sqlx::raw_sql(statement).execute(pool).await.map(drop),
    }
}

/// The rows of `statement` — run over the text protocol, as the command-line clients run it — printed as they
/// print them (see [`TestDatabase::sql_as_admin`]).
async fn rows_as_text(db: &Db, statement: &str) -> String {
    let sql = AssertSqlSafe(statement.to_owned());
    let lines: Vec<String> = match db {
        Db::MySql(pool) => {
            let rows = sqlx::raw_sql(sql).fetch_all(pool).await.unwrap_or_else(|error| panic!("{statement}: {error}"));
            rows.iter()
                .map(|row| {
                    (0..row.len())
                        .map(|index| match row.try_get_unchecked::<Option<&[u8]>, _>(index).unwrap() {
                            None => "NULL".to_owned(),
                            Some(bytes) => mysql_batch(bytes),
                        })
                        .collect::<Vec<_>>()
                        .join("\t")
                })
                .collect()
        }
        Db::PostgreSql(pool) => {
            let rows = sqlx::raw_sql(sql).fetch_all(pool).await.unwrap_or_else(|error| panic!("{statement}: {error}"));
            rows.iter()
                .map(|row| {
                    (0..row.len())
                        .map(|index| row.try_get_unchecked::<Option<&str>, _>(index).unwrap().unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join("|")
                })
                .collect()
        }
    };
    lines.join("\n").trim().to_owned()
}

/// A value as `mysql --batch` prints it.
fn mysql_batch(bytes: &[u8]) -> String {
    let mut escaped = Vec::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\0' => escaped.extend_from_slice(b"\\0"),
            b'\t' => escaped.extend_from_slice(b"\\t"),
            b'\n' => escaped.extend_from_slice(b"\\n"),
            b'\\' => escaped.extend_from_slice(b"\\\\"),
            other => escaped.push(other),
        }
    }
    String::from_utf8_lossy(&escaped).into_owned()
}

async fn connect_retrying(settings: &DbSettings) -> Db {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match Db::connect(settings).await {
            Ok(db) => return db,
            Err(failure) => {
                assert!(Instant::now() < deadline, "{} never answered: {failure}", settings.url.engine);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

/// Runs `work` to completion on a runtime of its own, on a thread of its own — callable from a test's runtime, from
/// a synchronous test, and from `Drop`, none of which can block on the caller's runtime.
fn blocking<T: Send>(work: impl Future<Output = T> + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime for the test database's statements")
                    .block_on(work)
            })
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

fn wait_until_ready(engine: Engine, server: &Container) {
    let deadline = Instant::now() + Duration::from_secs(180);
    let probe: Vec<String> = match engine {
        // A real query, not `mysqladmin ping`: the MySQL image answers pings from its temporary initialisation
        // server, which then stops and restarts.
        Engine::MySql => {
            ["mysql", "-uvectispire", &format!("-p{PASSWORD}"), "-h127.0.0.1", "-e", "select 1", "vectispire"]
                .map(str::to_owned)
                .to_vec()
        }
        Engine::PostgreSql => {
            ["psql", "-h", "127.0.0.1", "-U", "vectispire", "-tAc", "select 1"].map(str::to_owned).to_vec()
        }
    };
    let probe: Vec<&str> = probe.iter().map(String::as_str).collect();
    while !server.succeeds(&probe) {
        assert!(
            Instant::now() < deadline,
            "{engine} did not start: {}",
            docker(&["logs", "--tail", "40", &server.name])
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::mysql_batch;

    #[test]
    fn a_value_is_escaped_as_the_mysql_client_s_batch_mode_escapes_it() {
        assert_eq!(mysql_batch(b"a\tb\nc\\d\0e"), "a\\tb\\nc\\\\d\\0e");
        assert_eq!(mysql_batch(b"plain"), "plain");
    }
}
