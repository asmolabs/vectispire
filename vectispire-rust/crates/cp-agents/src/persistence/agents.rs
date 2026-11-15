//! `t_agent` — `AgentRepository`, every statement checked: `sqlx::query!` per engine, described by a migrated server
//! while compiling and kept in this crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh check cp-agents`). Each
//! carries its engine's tag, because the cache file is named after the SQL text alone.
//!
//! **An id that is not a UUID is a failure, not the nil UUID.** The rows were read by hand before, and an unreadable
//! `id` became `Uuid::default()` — an agent every later statement would have addressed as nobody. `char(36)` on both
//! engines, so the text is read and parsed here.

#![allow(dead_code)]

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_access::credentials::AgentRef;
use vectispire_cp_db::types::to_microseconds;
use vectispire_cp_db::{Db, Tx};

use crate::persistence::{DbError, StoreError};

/// Data reported by an agent during hello/heartbeat.
#[derive(Debug, Clone, Default)]
pub struct HeartbeatData<'a> {
    pub hostname: Option<&'a str>,
    pub platform: Option<&'a str>,
    pub version: Option<&'a str>,
    pub scanner_engine: Option<&'a str>,
    pub capabilities: Option<&'a str>,
    pub contract_version: Option<&'a str>,
    /// `WorkerExecutors`' stored form, written **whatever the hello carried — null included**: an agent replaced by an
    /// older one that announces none must claim as an unknown again, not under the state its predecessor left.
    pub executors: Option<String>,
    /// `at` when the hello carried executors, `None` when it did not.
    pub executors_reported_at: Option<OffsetDateTime>,
}

/// A row of `t_agent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub kind: String,
    pub labels: Option<String>,
    pub credentials_mode: String,
    pub enabled: bool,
    pub max_concurrent: Option<i32>,
    pub api_key_id: Option<Uuid>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub version: Option<String>,
    pub scanner_engine: Option<String>,
    pub capabilities: Option<String>,
    pub contract_version: Option<String>,
    pub sealing_public_key: Option<String>,
    pub sealing_key_generation: Option<i64>,
    pub signing_public_key: Option<String>,
    pub last_seen_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    /// What the agent's executors can run, as it last said — `WorkerExecutors`' stored form; `None` when it never
    /// said. Written by the hello and `record_executors` alone, never by `insert` or `update`: an administrator's
    /// change saved after a report must not put the old state back (Java's `updatable = false`).
    pub executors: Option<String>,
    pub executors_reported_at: Option<OffsetDateTime>,
}

/// A row as stored: the ids are `char(36)` text, made [`Uuid`]s by [`Stored::row`].
struct Stored {
    id: String,
    name: String,
    description: Option<String>,
    kind: String,
    labels: Option<String>,
    credentials_mode: String,
    enabled: bool,
    max_concurrent: Option<i32>,
    api_key_id: Option<String>,
    hostname: Option<String>,
    platform: Option<String>,
    version: Option<String>,
    scanner_engine: Option<String>,
    capabilities: Option<String>,
    contract_version: Option<String>,
    sealing_public_key: Option<String>,
    sealing_key_generation: Option<i64>,
    signing_public_key: Option<String>,
    last_seen_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    executors: Option<String>,
    executors_reported_at: Option<OffsetDateTime>,
}

impl Stored {
    fn row(self) -> Result<AgentRow, StoreError> {
        Ok(AgentRow {
            id: uuid_of(&self.id)?,
            name: self.name,
            description: self.description,
            kind: self.kind,
            labels: self.labels,
            credentials_mode: self.credentials_mode,
            enabled: self.enabled,
            max_concurrent: self.max_concurrent,
            api_key_id: self.api_key_id.as_deref().map(uuid_of).transpose()?,
            hostname: self.hostname,
            platform: self.platform,
            version: self.version,
            scanner_engine: self.scanner_engine,
            capabilities: self.capabilities,
            contract_version: self.contract_version,
            sealing_public_key: self.sealing_public_key,
            sealing_key_generation: self.sealing_key_generation,
            signing_public_key: self.signing_public_key,
            last_seen_at: self.last_seen_at,
            created_at: self.created_at,
            executors: self.executors,
            executors_reported_at: self.executors_reported_at,
        })
    }
}

/// A `char(36)` that is not a UUID: a row this side did not write.
fn uuid_of(text: &str) -> Result<Uuid, StoreError> {
    Uuid::try_parse(text.trim()).map_err(|error| StoreError(Box::new(error)))
}

fn not_built() -> StoreError {
    StoreError::from(DbError::EngineNotCompiled("this engine"))
}

fn rows(stored: Vec<Stored>) -> Result<Vec<AgentRow>, StoreError> {
    stored.into_iter().map(Stored::row).collect()
}

// MySQL's `datetime(6)` would be read as a zone-less `PrimitiveDateTime`; Hibernate stores UTC there, hence `: _`, the
// field's `OffsetDateTime`. `bit(1)` is read as a number unless told it is a `bool`.

pub async fn find_by_id(db: &Db, id: Uuid) -> Result<Option<AgentRow>, StoreError> {
    let id = id.as_hyphenated().to_string();
    let stored =
        match db {
            #[cfg(feature = "mysql-queries")]
            Db::MySql(pool) => sqlx::query_as!(
                Stored,
                r#"/* mysql */ select id, name, description, kind, labels, credentials_mode, enabled as "enabled: bool",
                max_concurrent, api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at as "last_seen_at: _",
                created_at as "created_at: _", executors, executors_reported_at as "executors_reported_at: _"
                from t_agent where id = ?"#,
                id
            )
            .fetch_optional(pool)
            .await?,
            #[cfg(feature = "postgres-queries")]
            Db::PostgreSql(pool) => {
                sqlx::query_as!(
                Stored,
                "/* postgres */ select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent,
                api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at, executors,
                executors_reported_at from t_agent where id = $1",
                id
            )
                .fetch_optional(pool)
                .await?
            }
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => return Err(not_built()),
        };
    stored.map(Stored::row).transpose()
}

pub async fn find_by_name(db: &Db, name: &str) -> Result<Option<AgentRow>, StoreError> {
    let stored =
        match db {
            #[cfg(feature = "mysql-queries")]
            Db::MySql(pool) => sqlx::query_as!(
                Stored,
                r#"/* mysql */ select id, name, description, kind, labels, credentials_mode, enabled as "enabled: bool",
                max_concurrent, api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at as "last_seen_at: _",
                created_at as "created_at: _", executors, executors_reported_at as "executors_reported_at: _"
                from t_agent where name = ?"#,
                name
            )
            .fetch_optional(pool)
            .await?,
            #[cfg(feature = "postgres-queries")]
            Db::PostgreSql(pool) => {
                sqlx::query_as!(
                Stored,
                "/* postgres */ select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent,
                api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at, executors,
                executors_reported_at from t_agent where name = $1",
                name
            )
                .fetch_optional(pool)
                .await?
            }
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => return Err(not_built()),
        };
    stored.map(Stored::row).transpose()
}

pub async fn find_by_api_key_id(db: &Db, api_key_id: Uuid) -> Result<Option<AgentRow>, StoreError> {
    let key = api_key_id.as_hyphenated().to_string();
    let stored =
        match db {
            #[cfg(feature = "mysql-queries")]
            Db::MySql(pool) => sqlx::query_as!(
                Stored,
                r#"/* mysql */ select id, name, description, kind, labels, credentials_mode, enabled as "enabled: bool",
                max_concurrent, api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at as "last_seen_at: _",
                created_at as "created_at: _", executors, executors_reported_at as "executors_reported_at: _"
                from t_agent where api_key_id = ?"#,
                key
            )
            .fetch_optional(pool)
            .await?,
            #[cfg(feature = "postgres-queries")]
            Db::PostgreSql(pool) => {
                sqlx::query_as!(
                Stored,
                "/* postgres */ select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent,
                api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at, executors,
                executors_reported_at from t_agent where api_key_id = $1",
                key
            )
                .fetch_optional(pool)
                .await?
            }
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => return Err(not_built()),
        };
    stored.map(Stored::row).transpose()
}

/// `findAllByOrderByNameAscIdAsc`.
pub async fn find_all_ordered(db: &Db) -> Result<Vec<AgentRow>, StoreError> {
    let stored =
        match db {
            #[cfg(feature = "mysql-queries")]
            Db::MySql(pool) => sqlx::query_as!(
                Stored,
                r#"/* mysql */ select id, name, description, kind, labels, credentials_mode, enabled as "enabled: bool",
                max_concurrent, api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at as "last_seen_at: _",
                created_at as "created_at: _", executors, executors_reported_at as "executors_reported_at: _"
                from t_agent order by name asc, id asc"#
            )
            .fetch_all(pool)
            .await?,
            #[cfg(feature = "postgres-queries")]
            Db::PostgreSql(pool) => {
                sqlx::query_as!(
                Stored,
                "/* postgres */ select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent,
                api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at, executors,
                executors_reported_at from t_agent order by name asc, id asc"
            )
                .fetch_all(pool)
                .await?
            }
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => return Err(not_built()),
        };
    rows(stored)
}

/// `findByEnabledTrue`.
pub async fn find_enabled(db: &Db) -> Result<Vec<AgentRow>, StoreError> {
    let stored =
        match db {
            #[cfg(feature = "mysql-queries")]
            Db::MySql(pool) => sqlx::query_as!(
                Stored,
                r#"/* mysql */ select id, name, description, kind, labels, credentials_mode, enabled as "enabled: bool",
                max_concurrent, api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at as "last_seen_at: _",
                created_at as "created_at: _", executors, executors_reported_at as "executors_reported_at: _"
                from t_agent where enabled = 1"#
            )
            .fetch_all(pool)
            .await?,
            #[cfg(feature = "postgres-queries")]
            Db::PostgreSql(pool) => {
                sqlx::query_as!(
                Stored,
                "/* postgres */ select id, name, description, kind, labels, credentials_mode, enabled, max_concurrent,
                api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at, executors,
                executors_reported_at from t_agent where enabled = true"
            )
                .fetch_all(pool)
                .await?
            }
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => return Err(not_built()),
        };
    rows(stored)
}

/// `save(new AgentEntity)`. The executors are never written here: the hello and `record_executors` alone write them.
pub async fn insert(tx: &mut Tx, row: &AgentRow) -> Result<(), StoreError> {
    let id = row.id.as_hyphenated().to_string();
    let api_key_id = row.api_key_id.map(|key| key.as_hyphenated().to_string());
    let last_seen_at = row.last_seen_at.map(to_microseconds);
    let created_at = to_microseconds(row.created_at);
    match tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(c) => {
            sqlx::query!(
                "/* mysql */ insert into t_agent (id, name, description, kind, labels, credentials_mode, enabled,
                max_concurrent, api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                id,
                row.name,
                row.description,
                row.kind,
                row.labels,
                row.credentials_mode,
                row.enabled,
                row.max_concurrent,
                api_key_id,
                row.hostname,
                row.platform,
                row.version,
                row.scanner_engine,
                row.capabilities,
                row.contract_version,
                row.sealing_public_key,
                row.sealing_key_generation,
                row.signing_public_key,
                last_seen_at,
                created_at
            )
            .execute(&mut **c)
            .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(c) => {
            sqlx::query!(
                "/* postgres */ insert into t_agent (id, name, description, kind, labels, credentials_mode, enabled,
                max_concurrent, api_key_id, hostname, platform, version, scanner_engine, capabilities, contract_version,
                sealing_public_key, sealing_key_generation, signing_public_key, last_seen_at, created_at)
                values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)",
                id,
                row.name,
                row.description,
                row.kind,
                row.labels,
                row.credentials_mode,
                row.enabled,
                row.max_concurrent,
                api_key_id,
                row.hostname,
                row.platform,
                row.version,
                row.scanner_engine,
                row.capabilities,
                row.contract_version,
                row.sealing_public_key,
                row.sealing_key_generation,
                row.signing_public_key,
                last_seen_at,
                created_at
            )
            .execute(&mut **c)
            .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    }
    Ok(())
}

/// `save(agent)` of an administrator's change: the columns the administration writes, and no others — the executors
/// least of all, which Java maps `updatable = false` so that a change saved after a report cannot put the old state back.
pub async fn update(tx: &mut Tx, row: &AgentRow) -> Result<bool, StoreError> {
    let id = row.id.as_hyphenated().to_string();
    let api_key_id = row.api_key_id.map(|key| key.as_hyphenated().to_string());
    let affected = match tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(c) => sqlx::query!(
            "/* mysql */ update t_agent set name = ?, description = ?, kind = ?, labels = ?, credentials_mode = ?,
            enabled = ?, max_concurrent = ?, api_key_id = ? where id = ?",
            row.name,
            row.description,
            row.kind,
            row.labels,
            row.credentials_mode,
            row.enabled,
            row.max_concurrent,
            api_key_id,
            id
        )
        .execute(&mut **c)
        .await?
        .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(c) => sqlx::query!(
            "/* postgres */ update t_agent set name = $1, description = $2, kind = $3, labels = $4,
            credentials_mode = $5, enabled = $6, max_concurrent = $7, api_key_id = $8 where id = $9",
            row.name,
            row.description,
            row.kind,
            row.labels,
            row.credentials_mode,
            row.enabled,
            row.max_concurrent,
            api_key_id,
            id
        )
        .execute(&mut **c)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(affected > 0)
}

pub async fn delete_by_id(tx: &mut Tx, id: Uuid) -> Result<bool, StoreError> {
    let id = id.as_hyphenated().to_string();
    let affected = match tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(c) => {
            sqlx::query!("/* mysql */ delete from t_agent where id = ?", id).execute(&mut **c).await?.rows_affected()
        }
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(c) => sqlx::query!("/* postgres */ delete from t_agent where id = $1", id)
            .execute(&mut **c)
            .await?
            .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(affected > 0)
}

/// `AgentRowLock`: the claim's serialising write, a sign of life at the same time. Whether the row exists.
pub async fn lock_for_claim(tx: &mut Tx, agent: Uuid, at: OffsetDateTime) -> Result<bool, StoreError> {
    let id = agent.as_hyphenated().to_string();
    let at = to_microseconds(at);
    let affected = match tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(c) => sqlx::query!("/* mysql */ update t_agent set last_seen_at = ? where id = ?", at, id)
            .execute(&mut **c)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(c) => sqlx::query!("/* postgres */ update t_agent set last_seen_at = $1 where id = $2", at, id)
            .execute(&mut **c)
            .await?
            .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(affected > 0)
}

/// Records that an agent was heard from, unless it already was since `stale_before`.
pub async fn record_seen(
    db: &Db,
    id: Uuid,
    at: OffsetDateTime,
    stale_before: OffsetDateTime,
) -> Result<bool, StoreError> {
    let id = id.as_hyphenated().to_string();
    let (at, stale_before) = (to_microseconds(at), to_microseconds(stale_before));
    let affected = match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!(
            "/* mysql */ update t_agent set last_seen_at = ? where id = ? and (last_seen_at is null or last_seen_at < ?)",
            at,
            id,
            stale_before
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!(
            "/* postgres */ update t_agent set last_seen_at = $1 where id = $2
            and (last_seen_at is null or last_seen_at < $3)",
            at,
            id,
            stale_before
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(affected > 0)
}

/// Records that an agent has just been heard from, and what it said about itself.
pub async fn record_heartbeat(
    db: &Db,
    id: Uuid,
    at: OffsetDateTime,
    data: &HeartbeatData<'_>,
) -> Result<bool, StoreError> {
    let id = id.as_hyphenated().to_string();
    let at = to_microseconds(at);
    let reported_at = data.executors_reported_at.map(to_microseconds);
    let executors = data.executors.as_deref();
    let affected = match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!(
            "/* mysql */ update t_agent set last_seen_at = ?, hostname = ?, platform = ?, version = ?,
            scanner_engine = ?, capabilities = ?, contract_version = ?, executors = ?, executors_reported_at = ?
            where id = ?",
            at,
            data.hostname,
            data.platform,
            data.version,
            data.scanner_engine,
            data.capabilities,
            data.contract_version,
            executors,
            reported_at,
            id
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!(
            "/* postgres */ update t_agent set last_seen_at = $1, hostname = $2, platform = $3, version = $4,
            scanner_engine = $5, capabilities = $6, contract_version = $7, executors = $8, executors_reported_at = $9
            where id = $10",
            at,
            data.hostname,
            data.platform,
            data.version,
            data.scanner_engine,
            data.capabilities,
            data.contract_version,
            executors,
            reported_at,
            id
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(affected > 0)
}

/// `recordExecutors`: what the agent's executors can run now, said after its hello because the answer changed — a
/// sign of life too. A statement of its own, never a save of the row. `false` when the agent no longer exists.
pub async fn record_executors(db: &Db, id: Uuid, executors: &str, at: OffsetDateTime) -> Result<bool, StoreError> {
    let id = id.as_hyphenated().to_string();
    let at = to_microseconds(at);
    let affected = match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!(
            "/* mysql */ update t_agent set executors = ?, executors_reported_at = ?, last_seen_at = ? where id = ?",
            executors,
            at,
            at,
            id
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!(
            "/* postgres */ update t_agent set executors = $1, executors_reported_at = $2, last_seen_at = $2 where id = $3",
            executors,
            at,
            id
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(affected > 0)
}

/// Records a sealing key whose signature was verified, if newer than the one held — or the same key again.
pub async fn accept_sealing_key(db: &Db, id: Uuid, key: &str, generation: i64) -> Result<bool, StoreError> {
    let id = id.as_hyphenated().to_string();
    let affected = match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!(
            "/* mysql */ update t_agent set sealing_public_key = ?, sealing_key_generation = ? where id = ?
            and (sealing_key_generation is null or sealing_key_generation < ?
                 or (sealing_key_generation = ? and sealing_public_key = ?))",
            key,
            generation,
            id,
            generation,
            generation,
            key
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!(
            "/* postgres */ update t_agent set sealing_public_key = $1, sealing_key_generation = $2 where id = $3
            and (sealing_key_generation is null or sealing_key_generation < $2
                 or (sealing_key_generation = $2 and sealing_public_key = $1))",
            key,
            generation,
            id
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(affected > 0)
}

/// Forgets the agent's sealing key and generation.
pub async fn forget_sealing_key(tx: &mut Tx, id: Uuid) -> Result<bool, StoreError> {
    let id = id.as_hyphenated().to_string();
    let affected = match tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(c) => sqlx::query!(
            "/* mysql */ update t_agent set sealing_public_key = null, sealing_key_generation = null where id = ?",
            id
        )
        .execute(&mut **c)
        .await?
        .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(c) => sqlx::query!(
            "/* postgres */ update t_agent set sealing_public_key = null, sealing_key_generation = null where id = $1",
            id
        )
        .execute(&mut **c)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(affected > 0)
}

/// Pins or unpins the signing public key for an agent.
pub async fn pin_signing_key(tx: &mut Tx, id: Uuid, key: Option<&str>) -> Result<bool, StoreError> {
    let id = id.as_hyphenated().to_string();
    let affected = match tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(c) => sqlx::query!("/* mysql */ update t_agent set signing_public_key = ? where id = ?", key, id)
            .execute(&mut **c)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(c) => {
            sqlx::query!("/* postgres */ update t_agent set signing_public_key = $1 where id = $2", key, id)
                .execute(&mut **c)
                .await?
                .rows_affected()
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(affected > 0)
}

/// Resolves an agent by its API key ID.
pub async fn by_api_key(db: &Db, key_id: Uuid) -> Result<Option<AgentRef>, StoreError> {
    let key = key_id.as_hyphenated().to_string();
    let row = match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ select id, name from t_agent where api_key_id = ?", key)
            .fetch_optional(pool)
            .await?
            .map(|row| (row.id, row.name)),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!("/* postgres */ select id, name from t_agent where api_key_id = $1", key)
            .fetch_optional(pool)
            .await?
            .map(|row| (row.id, row.name)),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    let Some((id, name)) = row else { return Ok(None) };
    Ok(Some(AgentRef { id: uuid_of(&id)?, name }))
}

/// Whether at least one agent is declared in `delegated` credentials mode.
pub async fn has_delegated_mode(tx: &mut Tx) -> Result<bool, StoreError> {
    let count = match tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(c) => {
            sqlx::query_scalar!(
                r#"/* mysql */ select count(*) as "count!: i64" from t_agent where credentials_mode = 'delegated'"#
            )
            .fetch_one(&mut **c)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(c) => {
            sqlx::query_scalar!(
                r#"/* postgres */ select count(*) as "count!" from t_agent where credentials_mode = 'delegated'"#
            )
            .fetch_one(&mut **c)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(not_built()),
    };
    Ok(count > 0)
}
