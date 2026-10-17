//! A throwaway database on each engine, migrated by `vectispire-migrate` — the runner held to the real Flyway by
//! its own oracle — and, for the oracle suite, the real Java audit log on the same database.
//!
//! The engines are the campaign's, by digest (`Engine.java`, `scripts/upgrade-drill.sh`). Every container is
//! `vs-rs-aud-*`, removed on drop; a missing Docker fails the test (AGENTS.md, "Never skip silently").

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use vectispire_cp_audit::{AuditLog, Clock, Mirror, MirrorEntry, NoMirror, SystemClock};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_db::{Db, Engine};
use vectispire_domain::secret::Secret;
use vectispire_testkit::docker::{Container, docker};

pub const MYSQL_IMAGE: &str = "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
pub const POSTGRES_IMAGE: &str =
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const PASSWORD: &str = "throwaway-audit-test"; // gitleaks:allow — invented, for a container removed after the test

/// A migrated database.
pub struct Migrated {
    pub engine: Engine,
    pub settings: DbSettings,
    pub port: u16,
    server: Container,
}

impl Migrated {
    pub async fn start(engine: Engine) -> Migrated {
        let server = match engine {
            Engine::MySql => Container::run(
                "aud-mysql",
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
                "aud-postgres",
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
        let migrated = Migrated { engine, settings, port, server };
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

    /// The URL the Java oracle connects with — the driver the control plane ships, without TLS, as the test
    /// containers serve it.
    pub fn jdbc_url(&self) -> String {
        match self.engine {
            Engine::MySql => {
                format!("jdbc:mysql://127.0.0.1:{}/vectispire?allowPublicKeyRetrieval=true&useSSL=false", self.port)
            }
            Engine::PostgreSql => format!("jdbc:postgresql://127.0.0.1:{}/vectispire", self.port),
        }
    }

    /// A statement as the superuser, inside the container — for what a test does behind the pool's back.
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

    /// The real Java audit log on this database (`oracle/oracle.sh`), in a JVM on UTC as the images run.
    pub fn oracle(&self, args: &[&str]) -> Result<String, String> {
        self.oracle_in_zone("UTC", args)
    }

    /// The same, in a JVM whose default time zone is `zone`.
    pub fn oracle_in_zone(&self, zone: &str, args: &[&str]) -> Result<String, String> {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("oracle/oracle.sh");
        let mut all = vec![args[0].to_owned(), self.jdbc_url(), "vectispire".to_owned(), PASSWORD.to_owned()];
        all.extend(args[1..].iter().map(|arg| (*arg).to_owned()));
        let output = Command::new(&script)
            .args(&all)
            .env("ORACLE_TIMEZONE", zone)
            .output()
            .expect("oracle/oracle.sh runs (it needs a JDK 25)");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if output.status.success() {
            Ok(stdout)
        } else {
            Err(format!("{stdout}\n{}", String::from_utf8_lossy(&output.stderr)))
        }
    }
}

fn wait_until_ready(engine: Engine, server: &Container) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        // A real query, not `mysqladmin ping`: the MySQL image answers pings from its temporary initialisation
        // server, which then stops and restarts.
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

/// A log with no mirror and no listener, on the system clock.
pub fn plain_log(db: &Db) -> AuditLog {
    AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(SystemClock), Vec::new())
}

/// A clock a test moves by hand.
#[derive(Debug)]
pub struct FixedClock(pub Mutex<OffsetDateTime>);

impl FixedClock {
    pub fn at(instant: OffsetDateTime) -> Arc<FixedClock> {
        Arc::new(FixedClock(Mutex::new(instant)))
    }

    pub fn set(&self, instant: OffsetDateTime) {
        *self.0.lock().unwrap() = instant;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

/// A mirror held in memory, which can be told to refuse.
#[derive(Debug, Default)]
pub struct MemoryMirror {
    pub lines: Mutex<Vec<MirrorEntry>>,
    pub refuse: std::sync::atomic::AtomicBool,
}

impl Mirror for MemoryMirror {
    fn append(&self, entry: &MirrorEntry) -> bool {
        if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        self.lines.lock().unwrap().push(entry.clone());
        true
    }

    fn configured(&self) -> bool {
        true
    }

    fn entry_hashes(&self) -> Result<Vec<String>, String> {
        Ok(self.lines.lock().unwrap().iter().map(|line| line.entry_hash.clone()).collect())
    }
}
