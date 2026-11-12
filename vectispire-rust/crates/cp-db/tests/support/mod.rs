//! A database of its own on each engine, with the schema **the real Flyway** built from the repository's
//! migrations — not a schema this crate wrote, which would only prove the crate agrees with itself.
//!
//! The server is `vectispire_cp_db::testing`'s: a throwaway container, or the shared one
//! `VECTISPIRE_TEST_MYSQL_URL` / `VECTISPIRE_TEST_POSTGRES_URL` names. Flyway is the version Spring Boot's BOM brings
//! (12.4.0), run from its published image with the placeholders `MigrationDialect` spells — so `vectispire-migrate`,
//! which the other crates' databases are built with, is not what this crate's schema checks stand on. A missing
//! Docker fails the test (AGENTS.md, "Never skip silently").

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

use vectispire_cp_db::settings::DbSettings;
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine};
use vectispire_testkit::docker::{docker, unique_name};

pub const FLYWAY_IMAGE: &str =
    "flyway/flyway:12.4.0@sha256:5be18367a9b3979a9f37234c371b80da457a448fb9577bd94d4bf24d923fafac";

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

/// A database Flyway migrated, and what it takes to reach it.
pub struct Migrated {
    pub engine: Engine,
    pub settings: DbSettings,
    database: TestDatabase,
}

impl Migrated {
    pub fn start(engine: Engine) -> Migrated {
        let database = TestDatabase::empty(engine);
        flyway(&database);
        let mut settings = database.settings.clone();
        settings.pool.max_connections = 4;
        Migrated { engine, settings, database }
    }

    pub async fn connect(&self) -> Db {
        Db::connect(&self.settings).await.expect("the migrated database")
    }

    /// A statement run as the server's administrator, for what the test sets up behind the pool's back.
    pub fn sql_as_admin(&self, statement: &str) -> String {
        self.database.sql_as_admin(statement)
    }
}

/// A network for Flyway's container to reach a throwaway server's by the alias `db`: created, and the server
/// attached, for the time of one run.
struct Network(String);

impl Network {
    fn around(server: &str) -> Network {
        let network = Network(unique_name("db-net"));
        docker(&["network", "create", &network.0]);
        docker(&["network", "connect", "--alias", "db", &network.0, server]);
        network
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["network", "rm", "-f", &self.0]).output();
    }
}

fn flyway(database: &TestDatabase) {
    let engine = database.engine;
    let migrations = migrations();
    let volume = format!("{}:/migrations:ro", migrations.display());
    let (scheme, port) = match engine {
        Engine::MySql => ("mysql", 3306),
        Engine::PostgreSql => ("postgresql", 5432),
    };
    // A throwaway server on a network with Flyway's container; a shared one as the host reaches it — through the
    // host's gateway when that is this machine, since a container's loopback is its own.
    let mut network = None;
    let mut reach: Vec<String> = Vec::new();
    let (host, port) = match database.container() {
        Some(server) => {
            let joined = Network::around(&server.name);
            reach.extend(["--network".to_owned(), joined.0.clone()]);
            network = Some(joined);
            ("db".to_owned(), port)
        }
        None if ["127.0.0.1", "localhost", "::1"].contains(&database.host()) => {
            reach.extend(["--add-host".to_owned(), "host.docker.internal:host-gateway".to_owned()]);
            ("host.docker.internal".to_owned(), database.port)
        }
        None => (database.host().to_owned(), database.port),
    };
    // Connector/J refuses caching_sha2 over a connection without TLS unless it may fetch the key; the server's own
    // key is what it would fetch.
    let options = if engine == Engine::MySql { "?allowPublicKeyRetrieval=true" } else { "" };
    let url = format!("jdbc:{scheme}://{host}:{port}/{}{options}", database.name());
    let mut arguments: Vec<String> = vec!["run".into(), "--rm".into()];
    arguments.extend(reach);
    arguments.extend([
        "-v".to_owned(),
        volume,
        FLYWAY_IMAGE.to_owned(),
        format!("-url={url}"),
        format!("-user={}", database.username()),
        format!("-password={}", database.password()),
        format!("-locations=filesystem:/migrations/common,filesystem:/migrations/{scheme}"),
    ]);
    arguments.extend(placeholders(engine).iter().map(|(name, value)| format!("-placeholders.{name}={value}")));
    arguments.push("migrate".into());
    let output = Command::new("docker").args(&arguments).output().expect("docker is required by this test");
    drop(network);
    assert!(
        output.status.success(),
        "Flyway did not migrate {engine}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
