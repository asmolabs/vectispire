//! A database of its own on each engine, migrated by **`vectispire-migrate`** from the repository's migrations — the
//! runner the Rust control plane starts with, itself held to the real Flyway (`crates/migrate/tests/oracle.rs`).
//!
//! The database is `vectispire_cp_db::testing`'s: in a throwaway container, or on the shared server
//! `VECTISPIRE_TEST_MYSQL_URL` / `VECTISPIRE_TEST_POSTGRES_URL` names (see that module).

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_access::credentials::{AgentDirectory, AgentRef, Clock, StoreError};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_domain::secret::Secret;

/// A database migrated by the Rust runner, and the pool on it. Field order is drop order: the pool, then the database.
pub struct Migrated {
    pub engine: Engine,
    pub db: Db,
    database: TestDatabase,
}

impl Migrated {
    pub async fn start(engine: Engine) -> Migrated {
        let database = TestDatabase::start(engine).await;
        let db = database.connect().await;
        Migrated { engine, db, database }
    }
}

/// A pool on a database somebody else migrated — the Java control plane's, in the cross-switch test.
pub async fn connect(url: &str, user: &str, password: &str) -> Db {
    let settings = DbSettings {
        url: DatabaseUrl::parse(url).unwrap(),
        username: user.into(),
        password: Secret::new(password),
        pool: PoolSettings { max_connections: 4, min_connections: 1, ..PoolSettings::default() },
        ca_pem: None,
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match Db::connect(&settings).await {
            Ok(db) => return db,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => panic!("{url}: {error}"),
        }
    }
}

/// Runs one statement, the test's own setup behind the service's back.
pub async fn execute(db: &Db, mysql: &str, postgres: &str, binds: &[Bind<'_>]) -> u64 {
    match db {
        Db::MySql(pool) => {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(mysql.to_owned()));
            for bind in binds {
                query = match bind {
                    Bind::Text(value) => query.bind(value.to_string()),
                    Bind::Int(value) => query.bind(*value),
                    Bind::Instant(value) => query.bind(*value),
                    Bind::Bool(value) => query.bind(*value),
                };
            }
            query.execute(pool).await.unwrap().rows_affected()
        }
        Db::PostgreSql(pool) => {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(postgres.to_owned()));
            for bind in binds {
                query = match bind {
                    Bind::Text(value) => query.bind(value.to_string()),
                    Bind::Int(value) => query.bind(*value),
                    Bind::Instant(value) => query.bind(*value),
                    Bind::Bool(value) => query.bind(*value),
                };
            }
            query.execute(pool).await.unwrap().rows_affected()
        }
    }
}

/// A value to bind.
#[derive(Clone, Copy)]
pub enum Bind<'a> {
    Text(&'a str),
    Int(i64),
    Instant(OffsetDateTime),
    Bool(bool),
}

/// An account, inserted as the accounts module would; answers its id.
pub async fn account(db: &Db, username: &str, role: &str, active: bool, must_change: bool) -> i64 {
    let now = now();
    execute(
        db,
        "insert into t_user (username, role, is_active, created_at, updated_at, must_change_password, mfa_enabled) \
         values (?, ?, ?, ?, ?, ?, false)",
        "insert into t_user (username, role, is_active, created_at, updated_at, must_change_password, mfa_enabled) \
         values ($1, $2, $3, $4, $5, $6, false)",
        &[
            Bind::Text(username),
            Bind::Text(role),
            Bind::Bool(active),
            Bind::Instant(now),
            Bind::Instant(now),
            Bind::Bool(must_change),
        ],
    )
    .await;
    scalar_i64(db, "select id from t_user where username = ?", "select id from t_user where username = $1", username)
        .await
}

pub async fn scalar_i64(db: &Db, mysql: &str, postgres: &str, text: &str) -> i64 {
    match db {
        Db::MySql(pool) => sqlx::query_scalar(sqlx::AssertSqlSafe(mysql.to_owned()))
            .bind(text.to_owned())
            .fetch_one(pool)
            .await
            .unwrap(),
        Db::PostgreSql(pool) => sqlx::query_scalar(sqlx::AssertSqlSafe(postgres.to_owned()))
            .bind(text.to_owned())
            .fetch_one(pool)
            .await
            .unwrap(),
    }
}

/// The agents module's `RegisteredAgents.byApiKey`, read straight from `t_agent` — what that module will implement.
#[derive(Debug)]
pub struct AgentsTable(pub Db);

impl AgentDirectory for AgentsTable {
    fn by_api_key<'a>(&'a self, key_id: Uuid) -> BoxFuture<'a, Result<Option<AgentRef>, StoreError>> {
        Box::pin(async move {
            let id = key_id.as_hyphenated().to_string();
            let row: Option<(String, String)> = match &self.0 {
                Db::MySql(pool) => sqlx::query_as("select id, name from t_agent where api_key_id = ?")
                    .bind(id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::from)?,
                Db::PostgreSql(pool) => sqlx::query_as("select id, name from t_agent where api_key_id = $1")
                    .bind(id)
                    .fetch_optional(pool)
                    .await
                    .map_err(StoreError::from)?,
            };
            Ok(row.map(|(id, name)| AgentRef { id: Uuid::try_parse(&id).unwrap(), name }))
        })
    }
}

/// An agent row pointing at `key_id`, inserted as the agents module would.
pub async fn agent(db: &Db, name: &str, key_id: Uuid) {
    let id = random_id();
    execute(
        db,
        "insert into t_agent (id, name, kind, credentials_mode, enabled, api_key_id, created_at) \
         values (?, ?, 'remote', 'delegated', true, ?, ?)",
        "insert into t_agent (id, name, kind, credentials_mode, enabled, api_key_id, created_at) \
         values ($1, $2, 'remote', 'delegated', true, $3, $4)",
        &[Bind::Text(&id), Bind::Text(name), Bind::Text(&key_id.as_hyphenated().to_string()), Bind::Instant(now())],
    )
    .await;
}

/// A random identifier, as Hibernate writes one into a `char(36)` column.
pub fn random_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes).into_uuid().as_hyphenated().to_string()
}

/// Now, at the microsecond both engines keep.
pub fn now() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(now.nanosecond() / 1_000 * 1_000).unwrap()
}

/// A clock the test moves by hand.
#[derive(Debug)]
pub struct HandClock(pub std::sync::Mutex<OffsetDateTime>);

impl HandClock {
    pub fn at(instant: OffsetDateTime) -> Arc<HandClock> {
        Arc::new(HandClock(std::sync::Mutex::new(instant)))
    }

    pub fn advance(&self, by: time::Duration) {
        let mut now = self.0.lock().unwrap();
        *now += by;
    }
}

impl Clock for HandClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}
