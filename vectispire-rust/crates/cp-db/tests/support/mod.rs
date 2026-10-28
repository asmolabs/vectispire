//! A throwaway database on each engine, with the schema **the real Flyway** built from the repository's
//! migrations — not a schema this crate wrote, which would only prove the crate agrees with itself.
//!
//! The engines are the campaign's, by digest (`Engine.java`, `scripts/upgrade-drill.sh`); Flyway is the
//! version Spring Boot's BOM brings (12.4.0), run from its published image with the placeholders
//! `MigrationDialect` spells. `vectispire-migrate` (plan, task 0.1) will replace this with the Rust
//! runner, checked against the same Flyway. Every container and network is `vs-rs-db-*`, removed on
//! drop; a missing Docker fails the test (AGENTS.md, "Never skip silently").

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_db::{Db, Engine};
use vectispire_domain::secret::Secret;
use vectispire_testkit::docker::{Container, docker, unique_name};

pub const MYSQL_IMAGE: &str = "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
pub const POSTGRES_IMAGE: &str =
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
pub const FLYWAY_IMAGE: &str =
    "flyway/flyway:12.4.0@sha256:5be18367a9b3979a9f37234c371b80da457a448fb9577bd94d4bf24d923fafac";

const PASSWORD: &str = "throwaway-test-database"; // gitleaks:allow — invented, for a container removed after the test

/// `MigrationDialect`'s table, positional as it is there.
fn placeholders(engine: Engine) -> [(&'static str, &'static str); 8] {
    match engine {
        Engine::MySql => [
            ("ts", "datetime(6)"),
            ("id", "bigint auto_increment primary key"),
            ("bool", "bit(1)"),
            ("true", "b'1'"),
            ("false", "b'0'"),
            ("text", "longtext"),
            ("double", "double"),
            ("bytes", "longblob"),
        ],
        Engine::PostgreSql => [
            ("ts", "timestamp with time zone"),
            ("id", "bigint generated always as identity primary key"),
            ("bool", "boolean"),
            ("true", "true"),
            ("false", "false"),
            ("text", "text"),
            ("double", "double precision"),
            ("bytes", "bytea"),
        ],
    }
}

pub fn migrations() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../vectispire-java/vectispire-core/src/main/resources/db/migration")
        .canonicalize()
        .expect("the Java tree's migrations, beside this workspace")
}

struct Network(String);

impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["network", "rm", &self.0]).output();
    }
}

/// A migrated database and what it takes to reach it. Field order is drop order: the server, then its network.
pub struct Migrated {
    pub engine: Engine,
    pub settings: DbSettings,
    server: Container,
    network: Network,
}

impl Migrated {
    pub fn start(engine: Engine) -> Migrated {
        let network = Network(unique_name("db-net"));
        docker(&["network", "create", &network.0]);
        let server = match engine {
            Engine::MySql => Container::run(
                "db-mysql",
                &[
                    "--network",
                    &network.0,
                    "--network-alias",
                    "db",
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
                    "--network",
                    &network.0,
                    "--network-alias",
                    "db",
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
        flyway(engine, &network.0);
        let (port, jdbc) = match engine {
            Engine::MySql => (server.host_port("3306/tcp"), "jdbc:mysql"),
            Engine::PostgreSql => (server.host_port("5432/tcp"), "jdbc:postgresql"),
        };
        let settings = DbSettings {
            url: DatabaseUrl::parse(&format!("{jdbc}://127.0.0.1:{port}/vectispire")).unwrap(),
            username: "vectispire".into(),
            password: Secret::new(PASSWORD),
            pool: PoolSettings { max_connections: 4, min_connections: 1, ..PoolSettings::default() },
            ca_pem: None,
        };
        Migrated { engine, settings, server, network }
    }

    pub async fn connect(&self) -> Db {
        Db::connect(&self.settings).await.expect("the migrated database")
    }

    /// A statement run as the superuser, inside the container — for what the test sets up behind the
    /// pool's back.
    pub fn sql_as_admin(&self, statement: &str) -> String {
        match self.engine {
            Engine::MySql => {
                self.server.exec(&["mysql", "-uroot", &format!("-p{PASSWORD}"), "-N", "vectispire", "-e", statement])
            }
            Engine::PostgreSql => self.server.exec(&["psql", "-U", "vectispire", "-tAc", statement]),
        }
    }
}

fn wait_until_ready(engine: Engine, server: &Container) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        // A real query, not `mysqladmin ping`: the MySQL image answers pings from its temporary
        // initialisation server, which then stops and restarts.
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

fn flyway(engine: Engine, network: &str) {
    let migrations = migrations();
    let volume = format!("{}:/migrations:ro", migrations.display());
    let (url, vendor) = match engine {
        // Connector/J refuses caching_sha2 over a connection without TLS unless it may fetch the key;
        // the throwaway server's own key is what it would fetch.
        Engine::MySql => ("jdbc:mysql://db:3306/vectispire?allowPublicKeyRetrieval=true", "mysql"),
        Engine::PostgreSql => ("jdbc:postgresql://db:5432/vectispire", "postgresql"),
    };
    let mut arguments: Vec<String> = [
        "run",
        "--rm",
        "--network",
        network,
        "-v",
        &volume,
        FLYWAY_IMAGE,
        &format!("-url={url}"),
        "-user=vectispire",
        &format!("-password={PASSWORD}"),
        &format!("-locations=filesystem:/migrations/common,filesystem:/migrations/{vendor}"),
    ]
    .iter()
    .map(|argument| (*argument).to_owned())
    .collect();
    arguments.extend(placeholders(engine).iter().map(|(name, value)| format!("-placeholders.{name}={value}")));
    arguments.push("migrate".into());
    let output = Command::new("docker").args(&arguments).output().expect("docker is required by this test");
    assert!(
        output.status.success(),
        "Flyway did not migrate {engine}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
