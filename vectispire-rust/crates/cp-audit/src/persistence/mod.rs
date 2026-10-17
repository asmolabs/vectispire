//! `t_audit_log` and `t_audit_chain_head` — every query of the module, on each engine.
//!
//! **Run-time statements, each one exercised on both engines by the crate's live suite** (`tests/engines.rs`)
//! rather than `query!` with an offline cache: the cache directory and its prepare script are `cp-db`'s, written
//! for that crate's own statements, and a module that described its statements against a database while
//! compiling would need the same machinery once per module. The text is fixed — no statement here is built from
//! a value — and the column types are read through `cp-db`'s `TextUuid` and `UtcInstant`, the mapping its
//! parity check holds to the schema.

use sqlx::Row as _;
use sqlx::mysql::MySqlRow;
use sqlx::postgres::PgRow;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::types::{TextUuid, UtcInstant};
use vectispire_cp_db::{Db, LockConflict, Tx};

/// A row of `t_audit_log` — `AuditLogEntity`. It stays in this layer: the module's API hands out
/// `Row`, as Java's routes hand out `AuditEntryView` and never the entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: Uuid,
    pub description: String,
    pub operation_type: String,
    pub resource_id: String,
    pub timestamp: OffsetDateTime,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub previous_hash: Option<String>,
    pub entry_hash: Option<String>,
}

/// A database failure, kept in this layer: a service names this type and never the driver's.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct DbError(#[from] sqlx::Error);

impl LockConflict for DbError {
    fn is_lock_conflict(&self) -> bool {
        vectispire_cp_db::is_lock_conflict(&self.0)
    }
}

impl DbError {
    /// A primary key or a unique constraint refused the row.
    pub fn is_unique_violation(&self) -> bool {
        match &self.0 {
            sqlx::Error::Database(database) => database.is_unique_violation(),
            _ => false,
        }
    }
}

fn mysql_entry(row: &MySqlRow) -> Result<Row, sqlx::Error> {
    Ok(Row {
        id: row.try_get::<TextUuid, _>("id")?.0,
        description: row.try_get("description")?,
        operation_type: row.try_get("operation_type")?,
        resource_id: row.try_get("resource_id")?,
        timestamp: row.try_get::<UtcInstant, _>("timestamp")?.0,
        user_id: row.try_get("user_id")?,
        ip_address: row.try_get("ip_address")?,
        user_agent: row.try_get("user_agent")?,
        previous_hash: row.try_get("previous_hash")?,
        entry_hash: row.try_get("entry_hash")?,
    })
}

fn postgres_entry(row: &PgRow) -> Result<Row, sqlx::Error> {
    Ok(Row {
        id: row.try_get::<TextUuid, _>("id")?.0,
        description: row.try_get("description")?,
        operation_type: row.try_get("operation_type")?,
        resource_id: row.try_get("resource_id")?,
        timestamp: row.try_get::<UtcInstant, _>("timestamp")?.0,
        user_id: row.try_get("user_id")?,
        ip_address: row.try_get("ip_address")?,
        user_agent: row.try_get("user_agent")?,
        previous_hash: row.try_get("previous_hash")?,
        entry_hash: row.try_get("entry_hash")?,
    })
}

/// `AuditChainHeadRepository.lock`: `select … for update` on V66's one row, held until the entry's transaction
/// ends — the next writer, on this instance, another, or a Java one, waits here instead of reading the same head.
/// `false` only if the row was deleted by hand, which the caller refuses rather than writing unlocked.
///
/// `for update` and not PostgreSQL's weaker `for no key update`: whatever Hibernate takes for a pessimistic write,
/// `for update` conflicts with it, so a Rust and a Java writer exclude each other either way.
pub async fn lock_chain(tx: &mut Tx) -> Result<bool, DbError> {
    let found = match tx {
        Tx::MySql(t) => sqlx::query("select id from t_audit_chain_head where id = ? for update")
            .bind(1_i32)
            .fetch_optional(&mut **t)
            .await?
            .is_some(),
        Tx::PostgreSql(t) => sqlx::query("select id from t_audit_chain_head where id = $1 for update")
            .bind(1_i32)
            .fetch_optional(&mut **t)
            .await?
            .is_some(),
    };
    Ok(found)
}

/// `findTopByOrderByTimestampDescIdDesc`: the entry the next one chains onto, in the verification's order
/// reversed — by timestamp alone, two entries of one millisecond would let the chain be built onto one and
/// verified against the other.
pub async fn head(tx: &mut Tx) -> Result<Option<Row>, DbError> {
    Ok(match tx {
        Tx::MySql(t) => sqlx::query(
            "select id, description, operation_type, resource_id, timestamp, user_id, ip_address, user_agent, \
             previous_hash, entry_hash from t_audit_log order by timestamp desc, id desc limit 1",
        )
        .fetch_optional(&mut **t)
        .await?
        .map(|row| mysql_entry(&row))
        .transpose()?,
        Tx::PostgreSql(t) => sqlx::query(
            "select id, description, operation_type, resource_id, timestamp, user_id, ip_address, user_agent, \
             previous_hash, entry_hash from t_audit_log order by timestamp desc, id desc limit 1",
        )
        .fetch_optional(&mut **t)
        .await?
        .map(|row| postgres_entry(&row))
        .transpose()?,
    })
}

/// The insert, issued at once — Java flushes inside its `try` for the same reason: a refusal must reach the
/// caller's error path before the mirror line is written.
pub async fn insert(tx: &mut Tx, entry: &Row) -> Result<(), DbError> {
    let id = TextUuid(entry.id);
    let at = UtcInstant(entry.timestamp);
    match tx {
        Tx::MySql(t) => {
            sqlx::query(
                "insert into t_audit_log (id, description, operation_type, resource_id, timestamp, user_id, \
                 ip_address, user_agent, previous_hash, entry_hash) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(&entry.description)
            .bind(&entry.operation_type)
            .bind(&entry.resource_id)
            .bind(at)
            .bind(&entry.user_id)
            .bind(&entry.ip_address)
            .bind(&entry.user_agent)
            .bind(&entry.previous_hash)
            .bind(&entry.entry_hash)
            .execute(&mut **t)
            .await?;
        }
        Tx::PostgreSql(t) => {
            sqlx::query(
                "insert into t_audit_log (id, description, operation_type, resource_id, timestamp, user_id, \
                 ip_address, user_agent, previous_hash, entry_hash) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(id)
            .bind(&entry.description)
            .bind(&entry.operation_type)
            .bind(&entry.resource_id)
            .bind(at)
            .bind(&entry.user_id)
            .bind(&entry.ip_address)
            .bind(&entry.user_agent)
            .bind(&entry.previous_hash)
            .bind(&entry.entry_hash)
            .execute(&mut **t)
            .await?;
        }
    }
    Ok(())
}

/// `findAllByOrderByTimestampAscIdAsc`: the whole log in chain order. Two entries of one millisecond by two
/// instances are a legitimate fork, and the id breaks the tie deterministically.
pub async fn all_in_chain_order(db: &Db) -> Result<Vec<Row>, DbError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query(
            "select id, description, operation_type, resource_id, timestamp, user_id, ip_address, user_agent, \
             previous_hash, entry_hash from t_audit_log order by timestamp asc, id asc",
        )
        .fetch_all(pool)
        .await?
        .iter()
        .map(mysql_entry)
        .collect::<Result<_, _>>()?,
        Db::PostgreSql(pool) => sqlx::query(
            "select id, description, operation_type, resource_id, timestamp, user_id, ip_address, user_agent, \
             previous_hash, entry_hash from t_audit_log order by timestamp asc, id asc",
        )
        .fetch_all(pool)
        .await?
        .iter()
        .map(postgres_entry)
        .collect::<Result<_, _>>()?,
    })
}

/// `findRecent`: the newest entries, for the screen.
pub async fn recent(db: &Db, limit: i64) -> Result<Vec<Row>, DbError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query(
            "select id, description, operation_type, resource_id, timestamp, user_id, ip_address, user_agent, \
             previous_hash, entry_hash from t_audit_log order by timestamp desc, id desc limit ?",
        )
        .bind(limit)
        .fetch_all(pool)
        .await?
        .iter()
        .map(mysql_entry)
        .collect::<Result<_, _>>()?,
        Db::PostgreSql(pool) => sqlx::query(
            "select id, description, operation_type, resource_id, timestamp, user_id, ip_address, user_agent, \
             previous_hash, entry_hash from t_audit_log order by timestamp desc, id desc limit $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await?
        .iter()
        .map(postgres_entry)
        .collect::<Result<_, _>>()?,
    })
}

/// `updateHashes`: rewrites one entry's hashes, for the rebuild and nothing else — a targeted update, so nothing
/// else of a row on this table is ever written.
pub async fn update_hashes(
    tx: &mut Tx,
    id: Uuid,
    previous_hash: Option<&str>,
    entry_hash: &str,
) -> Result<u64, DbError> {
    let id = TextUuid(id);
    Ok(match tx {
        Tx::MySql(t) => sqlx::query("update t_audit_log set previous_hash = ?, entry_hash = ? where id = ?")
            .bind(previous_hash)
            .bind(entry_hash)
            .bind(id)
            .execute(&mut **t)
            .await?
            .rows_affected(),
        Tx::PostgreSql(t) => sqlx::query("update t_audit_log set previous_hash = $1, entry_hash = $2 where id = $3")
            .bind(previous_hash)
            .bind(entry_hash)
            .bind(id)
            .execute(&mut **t)
            .await?
            .rows_affected(),
    })
}

/// `count()`.
pub async fn count(db: &Db) -> Result<i64, DbError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query("select count(*) from t_audit_log").fetch_one(pool).await?.try_get(0)?,
        Db::PostgreSql(pool) => sqlx::query("select count(*) from t_audit_log").fetch_one(pool).await?.try_get(0)?,
    })
}

/// `countByOperationTypeAndTimestampGreaterThanEqual`.
pub async fn count_since(db: &Db, operation_type: &str, since: OffsetDateTime) -> Result<i64, DbError> {
    let since = UtcInstant(since);
    Ok(match db {
        Db::MySql(pool) => sqlx::query("select count(*) from t_audit_log where operation_type = ? and timestamp >= ?")
            .bind(operation_type)
            .bind(since)
            .fetch_one(pool)
            .await?
            .try_get(0)?,
        Db::PostgreSql(pool) => {
            sqlx::query("select count(*) from t_audit_log where operation_type = $1 and timestamp >= $2")
                .bind(operation_type)
                .bind(since)
                .fetch_one(pool)
                .await?
                .try_get(0)?
        }
    })
}

/// `findResourcesNamed`, for one batch: which of these resources at least one entry of the operation names.
pub async fn resources_named(db: &Db, operation_type: &str, ids: &[String]) -> Result<Vec<String>, DbError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    Ok(match db {
        // `in (?, …)`, as Hibernate expands a collection: the comparison is the column's collation —
        // case-insensitive on MySQL — and a JSON test would compare bytes instead. The statement's text depends
        // on the batch's length and on nothing a caller wrote.
        Db::MySql(pool) => {
            let marks = vec!["?"; ids.len()].join(", ");
            let statement = format!(
                "select distinct resource_id from t_audit_log where operation_type = ? and resource_id in ({marks})"
            );
            let mut query = sqlx::query(sqlx::AssertSqlSafe(statement)).bind(operation_type);
            for id in ids {
                query = query.bind(id);
            }
            query.fetch_all(pool).await?.iter().map(|row| row.try_get(0)).collect::<Result<_, _>>()?
        }
        Db::PostgreSql(pool) => sqlx::query(
            "select distinct resource_id from t_audit_log where operation_type = $1 and resource_id = any($2)",
        )
        .bind(operation_type)
        .bind(ids)
        .fetch_all(pool)
        .await?
        .iter()
        .map(|row| row.try_get(0))
        .collect::<Result<_, _>>()?,
    })
}

/// `distinctOperationTypes`: the values actually present, so the filter offers nothing empty.
pub async fn distinct_operation_types(db: &Db) -> Result<Vec<String>, DbError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query("select distinct operation_type from t_audit_log order by operation_type asc")
            .fetch_all(pool)
            .await?
            .iter()
            .map(|row| row.try_get(0))
            .collect::<Result<_, _>>()?,
        Db::PostgreSql(pool) => {
            sqlx::query("select distinct operation_type from t_audit_log order by operation_type asc")
                .fetch_all(pool)
                .await?
                .iter()
                .map(|row| row.try_get(0))
                .collect::<Result<_, _>>()?
        }
    })
}

/// `findFiltered`'s criteria. Every filter optional, expressed as a null check rather than as several
/// statements: several statements are several orderings to keep in step, on the one table whose value is that it
/// reads the same to everybody.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub operation_type: Option<String>,
    pub user_id: Option<String>,
    /// Already lower-cased and wrapped in `%`, as the service builds it.
    pub pattern: Option<String>,
}

/// One page of the filtered log, newest first, and how many entries the filter matches.
pub async fn filtered(db: &Db, filter: &Filter, limit: i64, offset: i64) -> Result<(Vec<Row>, i64), DbError> {
    Ok(match db {
        Db::MySql(pool) => {
            let page = sqlx::query(
                "select id, description, operation_type, resource_id, timestamp, user_id, ip_address, user_agent, \
                 previous_hash, entry_hash from t_audit_log \
                 where (? is null or operation_type = ?) and (? is null or user_id = ?) \
                 and (? is null or lower(description) like ? or lower(resource_id) like ?) \
                 order by timestamp desc, id desc limit ? offset ?",
            )
            .bind(&filter.operation_type)
            .bind(&filter.operation_type)
            .bind(&filter.user_id)
            .bind(&filter.user_id)
            .bind(&filter.pattern)
            .bind(&filter.pattern)
            .bind(&filter.pattern)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
            .iter()
            .map(mysql_entry)
            .collect::<Result<Vec<_>, _>>()?;
            let total: i64 = sqlx::query(
                "select count(*) from t_audit_log \
                 where (? is null or operation_type = ?) and (? is null or user_id = ?) \
                 and (? is null or lower(description) like ? or lower(resource_id) like ?)",
            )
            .bind(&filter.operation_type)
            .bind(&filter.operation_type)
            .bind(&filter.user_id)
            .bind(&filter.user_id)
            .bind(&filter.pattern)
            .bind(&filter.pattern)
            .bind(&filter.pattern)
            .fetch_one(pool)
            .await?
            .try_get(0)?;
            (page, total)
        }
        Db::PostgreSql(pool) => {
            let page = sqlx::query(
                "select id, description, operation_type, resource_id, timestamp, user_id, ip_address, user_agent, \
                 previous_hash, entry_hash from t_audit_log \
                 where (cast($1 as varchar) is null or operation_type = $1) \
                 and (cast($2 as varchar) is null or user_id = $2) \
                 and (cast($3 as varchar) is null or lower(description) like $3 or lower(resource_id) like $3) \
                 order by timestamp desc, id desc limit $4 offset $5",
            )
            .bind(&filter.operation_type)
            .bind(&filter.user_id)
            .bind(&filter.pattern)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
            .iter()
            .map(postgres_entry)
            .collect::<Result<Vec<_>, _>>()?;
            let total: i64 = sqlx::query(
                "select count(*) from t_audit_log \
                 where (cast($1 as varchar) is null or operation_type = $1) \
                 and (cast($2 as varchar) is null or user_id = $2) \
                 and (cast($3 as varchar) is null or lower(description) like $3 or lower(resource_id) like $3)",
            )
            .bind(&filter.operation_type)
            .bind(&filter.user_id)
            .bind(&filter.pattern)
            .fetch_one(pool)
            .await?
            .try_get(0)?;
            (page, total)
        }
    })
}
