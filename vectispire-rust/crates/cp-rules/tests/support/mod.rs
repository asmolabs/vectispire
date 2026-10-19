//! Test harness for `vectispire-cp-rules`: MySQL and PostgreSQL containers, schema migration,
//! and database utilities.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::time::{Duration, Instant};

use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_db::{Db, Engine};
use vectispire_domain::secret::Secret;
use vectispire_testkit::docker::Container;

pub const MYSQL_IMAGE: &str = "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
pub const POSTGRES_IMAGE: &str =
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const PASSWORD: &str = "throwaway-rules-test"; // gitleaks:allow — test fixture

pub struct Migrated {
    pub engine: Engine,
    pub settings: DbSettings,
    server: Container,
}

impl Migrated {
    pub async fn start(engine: Engine) -> Migrated {
        let server = match engine {
            Engine::MySql => Container::run(
                "rules-mysql",
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
                "rules-postgres",
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
            Engine::PostgreSql => Command::new("docker")
                .args(["exec", &server.name, "pg_isready", "-U", "vectispire", "-d", "vectispire"])
                .output(),
        };
        if probe.map(|o| o.status.success()).unwrap_or(false) {
            return;
        }
        assert!(Instant::now() < deadline, "{engine} container did not start in time");
        std::thread::sleep(Duration::from_millis(500));
    }
}

pub async fn clean(db: &Db) {
    match db {
        Db::MySql(pool) => {
            sqlx::query("delete from t_semgrep_rule_set").execute(pool).await.unwrap();
        }
        Db::PostgreSql(pool) => {
            sqlx::query("delete from t_semgrep_rule_set").execute(pool).await.unwrap();
        }
    }
}
