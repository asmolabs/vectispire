//! The module's statements on MySQL, checked against a migrated server while compiling (`super`'s note).
//!
//! The id is `char(36)` and the instant `datetime(6)`, read and bound through `cp-db`'s `TextUuid` and
//! `UtcInstant` — the column overrides name them, as the parity check holds the schema to them. MySQL describes
//! no parameter type, so the binds are checked at run time by the live suite, on this engine.

use sqlx::MySqlConnection;
use sqlx::mysql::MySqlPool;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::types::{TextUuid, UtcInstant};

use super::{DbError, Filter, Row};

/// A row from any statement selecting the entity's columns, with the overrides below.
macro_rules! row {
    ($record:expr) => {{
        let record = $record;
        Row {
            id: record.id.0,
            description: record.description,
            operation_type: record.operation_type,
            resource_id: record.resource_id,
            timestamp: record.timestamp.0,
            user_id: record.user_id,
            ip_address: record.ip_address,
            user_agent: record.user_agent,
            previous_hash: record.previous_hash,
            entry_hash: record.entry_hash,
        }
    }};
}

pub async fn lock_chain(conn: &mut MySqlConnection) -> Result<bool, DbError> {
    Ok(sqlx::query!("/* mysql */ select id from t_audit_chain_head where id = ? for update", 1_i32)
        .fetch_optional(conn)
        .await?
        .is_some())
}

pub async fn head(conn: &mut MySqlConnection) -> Result<Option<Row>, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ select id as `id: TextUuid`, description, operation_type, resource_id, \
         timestamp as `timestamp: UtcInstant`, user_id, ip_address, user_agent, previous_hash, entry_hash \
         from t_audit_log order by timestamp desc, id desc limit 1"
    )
    .fetch_optional(conn)
    .await?
    .map(|record| row!(record)))
}

pub async fn insert(conn: &mut MySqlConnection, entry: &Row) -> Result<(), DbError> {
    sqlx::query!(
        "/* mysql */ insert into t_audit_log (id, description, operation_type, resource_id, timestamp, user_id, \
         ip_address, user_agent, previous_hash, entry_hash) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        TextUuid(entry.id),
        entry.description,
        entry.operation_type,
        entry.resource_id,
        UtcInstant(entry.timestamp),
        entry.user_id,
        entry.ip_address,
        entry.user_agent,
        entry.previous_hash,
        entry.entry_hash
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn all_in_chain_order(pool: &MySqlPool) -> Result<Vec<Row>, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ select id as `id: TextUuid`, description, operation_type, resource_id, \
         timestamp as `timestamp: UtcInstant`, user_id, ip_address, user_agent, previous_hash, entry_hash \
         from t_audit_log order by timestamp asc, id asc"
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|record| row!(record))
    .collect())
}

pub async fn recent(pool: &MySqlPool, limit: i64) -> Result<Vec<Row>, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ select id as `id: TextUuid`, description, operation_type, resource_id, \
         timestamp as `timestamp: UtcInstant`, user_id, ip_address, user_agent, previous_hash, entry_hash \
         from t_audit_log order by timestamp desc, id desc limit ?",
        limit
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|record| row!(record))
    .collect())
}

pub async fn update_hashes(
    conn: &mut MySqlConnection,
    id: Uuid,
    previous_hash: Option<&str>,
    entry_hash: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_audit_log set previous_hash = ?, entry_hash = ? where id = ?",
        previous_hash,
        entry_hash,
        TextUuid(id)
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn count(pool: &MySqlPool) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!("/* mysql */ select count(*) from t_audit_log").fetch_one(pool).await?)
}

pub async fn count_since(pool: &MySqlPool, operation_type: &str, since: OffsetDateTime) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        "/* mysql */ select count(*) from t_audit_log where operation_type = ? and timestamp >= ?",
        operation_type,
        UtcInstant(since)
    )
    .fetch_one(pool)
    .await?)
}

/// `in (?, …)`, as Hibernate expands a collection: the comparison is the column's collation — case-insensitive on
/// MySQL — where a JSON array would compare bytes. **The one run-time statement of the module**: its text follows
/// the batch's length and nothing a caller wrote, so it cannot be described once at compile time.
pub async fn resources_named(pool: &MySqlPool, operation_type: &str, ids: &[String]) -> Result<Vec<String>, DbError> {
    let marks = vec!["?"; ids.len()].join(", ");
    let statement = format!(
        "/* mysql */ select distinct resource_id from t_audit_log where operation_type = ? and resource_id in ({marks})"
    );
    let mut query = sqlx::query_scalar(sqlx::AssertSqlSafe(statement)).bind(operation_type);
    for id in ids {
        query = query.bind(id);
    }
    Ok(query.fetch_all(pool).await?)
}

pub async fn distinct_operation_types(pool: &MySqlPool) -> Result<Vec<String>, DbError> {
    Ok(sqlx::query_scalar!("/* mysql */ select distinct operation_type from t_audit_log order by operation_type asc")
        .fetch_all(pool)
        .await?)
}

pub async fn filtered(pool: &MySqlPool, filter: &Filter, limit: i64, offset: i64) -> Result<(Vec<Row>, i64), DbError> {
    let page = sqlx::query!(
        "/* mysql */ select id as `id: TextUuid`, description, operation_type, resource_id, \
         timestamp as `timestamp: UtcInstant`, user_id, ip_address, user_agent, previous_hash, entry_hash \
         from t_audit_log \
         where (? is null or operation_type = ?) and (? is null or user_id = ?) \
         and (? is null or lower(description) like ? or lower(resource_id) like ?) \
         order by timestamp desc, id desc limit ? offset ?",
        filter.operation_type,
        filter.operation_type,
        filter.user_id,
        filter.user_id,
        filter.pattern,
        filter.pattern,
        filter.pattern,
        limit,
        offset
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|record| row!(record))
    .collect();
    let total = sqlx::query_scalar!(
        "/* mysql */ select count(*) from t_audit_log \
         where (? is null or operation_type = ?) and (? is null or user_id = ?) \
         and (? is null or lower(description) like ? or lower(resource_id) like ?)",
        filter.operation_type,
        filter.operation_type,
        filter.user_id,
        filter.user_id,
        filter.pattern,
        filter.pattern,
        filter.pattern
    )
    .fetch_one(pool)
    .await?;
    Ok((page, total))
}
