//! Throwaway database servers, schema dumps, and the Java oracle, for the runner's tests.
//!
//! **The servers are the images the repository pins** — those `scripts/upgrade-drill.sh` and CI's job
//! services run (`scripts/check-db-pins.py` holds them to `Engine.java`): MySQL 9.4 and PostgreSQL 17.
//! Each test starts its own, named `vs-rs-mig-*`, removed when it ends.

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use sqlx::Row as _;
use vectispire_migrate::{Database, Engine};
use vectispire_testkit::docker::Container;

pub const MYSQL_IMAGE: &str =
    "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
pub const POSTGRES_IMAGE: &str =
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
pub const USER: &str = "vectispire";
pub const PASSWORD: &str = "throwaway-test-only";

/// A database server for one test.
#[derive(Debug)]
pub struct Server {
    pub engine: Engine,
    pub container: Container,
    pub port: u16,
}

impl Server {
    pub fn start(engine: Engine) -> Server {
        let container = match engine {
            Engine::MySql => Container::run(
                "mig-mysql",
                &[
                    "-p",
                    "127.0.0.1::3306",
                    "-e",
                    "MYSQL_ROOT_PASSWORD=root-throwaway",
                    "-e",
                    "MYSQL_DATABASE=vectispire",
                    "-e",
                    &format!("MYSQL_USER={USER}"),
                    "-e",
                    &format!("MYSQL_PASSWORD={PASSWORD}"),
                    MYSQL_IMAGE,
                ],
            ),
            Engine::PostgreSql => Container::run(
                "mig-pg",
                &[
                    "-p",
                    "127.0.0.1::5432",
                    "-e",
                    &format!("POSTGRES_USER={USER}"),
                    "-e",
                    &format!("POSTGRES_PASSWORD={PASSWORD}"),
                    "-e",
                    "POSTGRES_DB=vectispire",
                    POSTGRES_IMAGE,
                ],
            ),
        };
        let port = container.host_port(match engine {
            Engine::MySql => "3306/tcp",
            Engine::PostgreSql => "5432/tcp",
        });
        Server { engine, container, port }
    }

    pub fn url(&self) -> String {
        match self.engine {
            Engine::MySql => format!("mysql://{USER}:{PASSWORD}@127.0.0.1:{}/vectispire", self.port),
            Engine::PostgreSql => format!("postgres://{USER}:{PASSWORD}@127.0.0.1:{}/vectispire", self.port),
        }
    }

    pub fn jdbc_url(&self) -> String {
        match self.engine {
            Engine::MySql => format!(
                "jdbc:mysql://127.0.0.1:{}/vectispire?allowPublicKeyRetrieval=true&useSSL=false",
                self.port
            ),
            Engine::PostgreSql => format!("jdbc:postgresql://127.0.0.1:{}/vectispire", self.port),
        }
    }

    /// A pool once the server answers; the entrypoints restart the server once during initialisation,
    /// so a first successful connection is not enough — a query must succeed twice, a second apart.
    pub async fn database(&self) -> Database {
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut successes = 0;
        loop {
            let attempt = self.connect().await;
            match attempt {
                Ok(database) if ping(&database).await => {
                    successes += 1;
                    if successes == 2 {
                        return database;
                    }
                }
                _ => successes = 0,
            }
            assert!(Instant::now() < deadline, "{:?} never answered", self.engine);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn connect(&self) -> Result<Database, sqlx::Error> {
        Ok(match self.engine {
            Engine::MySql => Database::MySql(
                sqlx::mysql::MySqlPoolOptions::new().max_connections(4).connect(&self.url()).await?,
            ),
            Engine::PostgreSql => Database::PostgreSql(
                sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&self.url()).await?,
            ),
        })
    }

    /// The real Flyway with the Java configuration (`oracle/oracle.sh`), on this server.
    pub fn oracle(&self, command: &str, root: Option<&Path>, target: Option<&str>) -> Result<String, String> {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("oracle/oracle.sh");
        let mut args = vec![
            command.to_owned(),
            self.jdbc_url(),
            USER.to_owned(),
            PASSWORD.to_owned(),
            self.engine.vendor().to_owned(),
            root.map_or("-".to_owned(), |root| root.display().to_string()),
        ];
        if let Some(target) = target {
            args.push(target.to_owned());
        }
        let output = Command::new(&script).args(&args).output().expect("oracle/oracle.sh runs (it needs a JDK 25)");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if output.status.success() { Ok(stdout) } else { Err(format!("{stdout}\n{stderr}")) }
    }
}

async fn ping(database: &Database) -> bool {
    match database {
        Database::MySql(pool) => sqlx::query("SELECT 1").execute(pool).await.is_ok(),
        Database::PostgreSql(pool) => sqlx::query("SELECT 1").execute(pool).await.is_ok(),
    }
}

/// Runs a statement directly, to set a test's scene.
pub async fn execute(database: &Database, sql: &str) {
    match database {
        Database::MySql(pool) => drop(sqlx::raw_sql(sql).execute(pool).await.unwrap()),
        Database::PostgreSql(pool) => drop(sqlx::raw_sql(sql).execute(pool).await.unwrap()),
    }
}

/// The history as the tests compare it: everything but the time and duration of each run.
pub async fn history(database: &Database) -> Vec<String> {
    let sql = "SELECT installed_rank, version, description, type, script, checksum, installed_by, success \
               FROM flyway_schema_history ORDER BY installed_rank";
    let line = |rank: i32, version: Option<String>, description: String, kind: String, script: String, checksum: Option<i32>, by: String, success: bool| {
        format!("{rank}\t{}\t{description}\t{kind}\t{script}\t{}\t{by}\t{success}", version.unwrap_or_default(), checksum.map_or("null".to_owned(), |c| c.to_string()))
    };
    match database {
        Database::MySql(pool) => sqlx::query(sql)
            .fetch_all(pool)
            .await
            .unwrap()
            .iter()
            .map(|r| line(r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5), r.get(6), r.get(7)))
            .collect(),
        Database::PostgreSql(pool) => sqlx::query(sql)
            .fetch_all(pool)
            .await
            .unwrap()
            .iter()
            .map(|r| line(r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5), r.get(6), r.get(7)))
            .collect(),
    }
}

/// The schema, as text two databases can be compared by: tables, columns with their types,
/// nullability and defaults, indexes, constraints and routines — everything a migration creates.
pub async fn schema(database: &Database) -> String {
    let mut lines: Vec<String> = Vec::new();
    match database {
        Database::MySql(pool) => {
            let queries = [
                "SELECT CONCAT_WS('|', 'table', table_name, table_type, engine, table_collation) FROM information_schema.tables WHERE table_schema = DATABASE()",
                "SELECT CONCAT_WS('|', 'column', table_name, ordinal_position, column_name, column_type, is_nullable, IFNULL(column_default, '<null>'), extra, IFNULL(collation_name, '-')) FROM information_schema.columns WHERE table_schema = DATABASE()",
                "SELECT CONCAT_WS('|', 'index', table_name, index_name, non_unique, seq_in_index, column_name, IFNULL(sub_part, '-'), index_type) FROM information_schema.statistics WHERE table_schema = DATABASE()",
                "SELECT CONCAT_WS('|', 'constraint', table_name, constraint_name, constraint_type, IFNULL(enforced, '-')) FROM information_schema.table_constraints WHERE table_schema = DATABASE()",
                "SELECT CONCAT_WS('|', 'key', table_name, constraint_name, column_name, ordinal_position, IFNULL(referenced_table_name, '-'), IFNULL(referenced_column_name, '-')) FROM information_schema.key_column_usage WHERE table_schema = DATABASE()",
                "SELECT CONCAT_WS('|', 'reference', table_name, constraint_name, update_rule, delete_rule) FROM information_schema.referential_constraints WHERE constraint_schema = DATABASE()",
                "SELECT CONCAT_WS('|', 'check', constraint_name, check_clause) FROM information_schema.check_constraints WHERE constraint_schema = DATABASE()",
                "SELECT CONCAT_WS('|', 'routine', routine_name, routine_type) FROM information_schema.routines WHERE routine_schema = DATABASE()",
                "SELECT CONCAT_WS('|', 'trigger', trigger_name, event_object_table) FROM information_schema.triggers WHERE trigger_schema = DATABASE()",
            ];
            for query in queries {
                for row in sqlx::query(query).fetch_all(pool).await.unwrap() {
                    // CONCAT_WS over information_schema's columns comes back as text or as binary
                    // depending on the columns' collations; either is read as text.
                    let value = row
                        .try_get::<String, _>(0)
                        .or_else(|_| row.try_get::<Vec<u8>, _>(0).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
                        .unwrap();
                    lines.push(value);
                }
            }
        }
        Database::PostgreSql(pool) => {
            let queries = [
                "SELECT concat_ws('|', 'table', table_name, table_type) FROM information_schema.tables WHERE table_schema = current_schema()",
                "SELECT concat_ws('|', 'column', table_name, ordinal_position, column_name, data_type, udt_name, character_maximum_length, numeric_precision, is_nullable, coalesce(column_default, '<null>'), is_identity, identity_generation) FROM information_schema.columns WHERE table_schema = current_schema()",
                "SELECT concat_ws('|', 'index', tablename, indexname, indexdef) FROM pg_indexes WHERE schemaname = current_schema()",
                "SELECT concat_ws('|', 'constraint', t.relname, c.conname, c.contype, pg_get_constraintdef(c.oid)) FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = current_schema()",
                "SELECT concat_ws('|', 'sequence', sequence_name, data_type, start_value, increment) FROM information_schema.sequences WHERE sequence_schema = current_schema()",
                "SELECT concat_ws('|', 'routine', p.proname) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = current_schema()",
                "SELECT concat_ws('|', 'type', t.typname, t.typtype) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = current_schema() AND t.typtype IN ('e', 'd')",
            ];
            for query in queries {
                for row in sqlx::query(query).fetch_all(pool).await.unwrap() {
                    lines.push(row.get(0));
                }
            }
        }
    }
    lines.sort();
    lines.join("\n") + "\n"
}

/// `db/migration` as another commit holds it, extracted into a directory that lives as long as the
/// returned value.
pub fn migrations_at(commit: &str) -> tempfile::TempDir {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let path = "vectispire-java/vectispire-core/src/main/resources/db/migration";
    let listing = Command::new("git")
        .current_dir(&repo)
        .args(["ls-tree", "-r", "--name-only", commit, path])
        .output()
        .expect("git runs");
    assert!(listing.status.success(), "{commit} is not in this repository: {}", String::from_utf8_lossy(&listing.stderr));
    let directory = tempfile::tempdir().unwrap();
    for file in String::from_utf8(listing.stdout).unwrap().lines() {
        let relative = file.strip_prefix(&format!("{path}/")).unwrap();
        let destination = directory.path().join(relative);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        let bytes = Command::new("git").current_dir(&repo).args(["show", &format!("{commit}:{file}")]).output().unwrap();
        assert!(bytes.status.success());
        std::fs::write(destination, bytes.stdout).unwrap();
    }
    directory
}
