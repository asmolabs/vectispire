//! A throwaway database on each engine, migrated by `vectispire-migrate` — the runner proven against the real
//! Flyway 12.4 in both directions (its `tests/oracle.rs`), so the schema is the one the Java control plane builds.
//!
//! The engines are the campaign's, by digest. Containers are `vs-rs-acc-*`, removed on drop; a missing Docker fails
//! the test (AGENTS.md, "Never skip silently").
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use vectispire_cp_access::SessionsAndKeys;
use vectispire_cp_access::accounts::{RevokedKey, SessionHash, StoreError};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_db::{Db, Engine, Tx};
use vectispire_domain::secret::Secret;
use vectispire_testkit::docker::{Container, docker};

pub const MYSQL_IMAGE: &str = "mysql:9.4.0@sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2";
pub const POSTGRES_IMAGE: &str =
    "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94";
const PASSWORD: &str = "throwaway-test-database-acc"; // gitleaks:allow — invented, for a container removed after the test

pub struct Migrated {
    pub engine: Engine,
    pub settings: DbSettings,
    pub server: Container,
}

impl Migrated {
    pub async fn start(engine: Engine) -> Migrated {
        let server = match engine {
            Engine::MySql => Container::run(
                "acc-mysql",
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
                ],
            ),
            Engine::PostgreSql => Container::run(
                "acc-postgres",
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
            pool: PoolSettings { max_connections: 4, min_connections: 1, ..PoolSettings::default() },
            ca_pem: None,
        };
        let migrated = Migrated { engine, settings, server };
        let db = migrated.connect().await;
        let database = match &db {
            Db::MySql(pool) => vectispire_migrate::Database::MySql(pool.clone()),
            Db::PostgreSql(pool) => vectispire_migrate::Database::PostgreSql(pool.clone()),
        };
        let report = vectispire_migrate::run(&database, &vectispire_migrate::Options::default()).await.unwrap();
        assert!(report.applied.len() > 80, "{engine}: {} migrations applied", report.applied.len());
        db.close().await;
        migrated
    }

    pub async fn connect(&self) -> Db {
        Db::connect(&self.settings).await.expect("the migrated database")
    }

    /// A statement as the database's owner, inside the container — what the test arranges behind the pool's back.
    pub fn sql(&self, statement: &str) -> String {
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

/// `t_session` and `t_api_key` as `SessionRepository` and `ApiKeyRepository` write them — the credentials task's
/// rows, written here by plain SQL so that the account transactions are proven to commit and roll back with them.
#[derive(Debug, Clone, Copy)]
pub struct RawCredentials;

impl SessionsAndKeys for RawCredentials {
    async fn delete_sessions(&self, tx: &mut Tx, user_id: i64) -> Result<(), StoreError> {
        match tx {
            Tx::MySql(tx) => {
                sqlx::query("delete from t_session where user_id = ?").bind(user_id).execute(&mut **tx).await.map(drop)
            }
            Tx::PostgreSql(tx) => {
                sqlx::query("delete from t_session where user_id = $1").bind(user_id).execute(&mut **tx).await.map(drop)
            }
        }
        .map_err(|error| StoreError(Box::new(error)))
    }

    async fn delete_sessions_except(&self, tx: &mut Tx, user_id: i64, keep: &SessionHash) -> Result<(), StoreError> {
        match tx {
            Tx::MySql(tx) => sqlx::query("delete from t_session where user_id = ? and token_hash <> ?")
                .bind(user_id)
                .bind(&keep.0)
                .execute(&mut **tx)
                .await
                .map(drop),
            Tx::PostgreSql(tx) => sqlx::query("delete from t_session where user_id = $1 and token_hash <> $2")
                .bind(user_id)
                .bind(&keep.0)
                .execute(&mut **tx)
                .await
                .map(drop),
        }
        .map_err(|error| StoreError(Box::new(error)))
    }

    async fn revoke_owned_keys(&self, _tx: &mut Tx, _user_id: i64) -> Result<Vec<RevokedKey>, StoreError> {
        Ok(Vec::new())
    }

    async fn count_active_by_user(&self, db: &Db, at: OffsetDateTime) -> Result<HashMap<i64, u64>, StoreError> {
        let at = vectispire_cp_db::types::UtcInstant(at);
        let rows: Vec<(i64, i64)> = match db {
            Db::MySql(pool) => {
                sqlx::query_as("select user_id, count(token_hash) from t_session where expires_at > ? group by user_id")
                    .bind(at)
                    .fetch_all(pool)
                    .await
            }
            Db::PostgreSql(pool) => {
                sqlx::query_as(
                    "select user_id, count(token_hash) from t_session where expires_at > $1 group by user_id",
                )
                .bind(at)
                .fetch_all(pool)
                .await
            }
        }
        .map_err(|error| StoreError(Box::new(error)))?;
        Ok(rows.into_iter().map(|(user, count)| (user, u64::try_from(count).unwrap_or(0))).collect())
    }
}
