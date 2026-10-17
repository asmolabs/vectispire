//! The module's statements on PostgreSQL, checked against a migrated server while compiling (`super`'s note).
//!
//! The id is `char(36)` and the instant `timestamp with time zone`, read and bound through `cp-db`'s `TextUuid`
//! and `UtcInstant`. PostgreSQL describes its parameters, so a bind of the wrong type does not build; the two
//! custom types are bound `as _`, the macro's override for a type it cannot name, and checked by the live suite.

use sqlx::PgConnection;
use sqlx::postgres::PgPool;
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

pub async fn lock_chain(conn: &mut PgConnection) -> Result<bool, DbError> {
    Ok(sqlx::query!("/* postgres */ select id from t_audit_chain_head where id = $1 for update", 1_i32)
        .fetch_optional(conn)
        .await?
        .is_some())
}

pub async fn head(conn: &mut PgConnection) -> Result<Option<Row>, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ select id as "id: TextUuid", description, operation_type, resource_id,
         timestamp as "timestamp: UtcInstant", user_id, ip_address, user_agent, previous_hash, entry_hash
         from t_audit_log order by timestamp desc, id desc limit 1"#
    )
    .fetch_optional(conn)
    .await?
    .map(|record| row!(record)))
}

pub async fn insert(conn: &mut PgConnection, entry: &Row) -> Result<(), DbError> {
    sqlx::query!(
        "/* postgres */ insert into t_audit_log (id, description, operation_type, resource_id, timestamp, user_id, \
         ip_address, user_agent, previous_hash, entry_hash) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        TextUuid(entry.id) as _,
        entry.description,
        entry.operation_type,
        entry.resource_id,
        UtcInstant(entry.timestamp) as _,
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

pub async fn all_in_chain_order(pool: &PgPool) -> Result<Vec<Row>, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ select id as "id: TextUuid", description, operation_type, resource_id,
         timestamp as "timestamp: UtcInstant", user_id, ip_address, user_agent, previous_hash, entry_hash
         from t_audit_log order by timestamp asc, id asc"#
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|record| row!(record))
    .collect())
}

pub async fn recent(pool: &PgPool, limit: i64) -> Result<Vec<Row>, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ select id as "id: TextUuid", description, operation_type, resource_id,
         timestamp as "timestamp: UtcInstant", user_id, ip_address, user_agent, previous_hash, entry_hash
         from t_audit_log order by timestamp desc, id desc limit $1"#,
        limit
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|record| row!(record))
    .collect())
}

pub async fn update_hashes(
    conn: &mut PgConnection,
    id: Uuid,
    previous_hash: Option<&str>,
    entry_hash: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_audit_log set previous_hash = $1, entry_hash = $2 where id = $3",
        previous_hash,
        entry_hash,
        TextUuid(id) as _
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn count(pool: &PgPool) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(r#"/* postgres */ select count(*) as "count!" from t_audit_log"#).fetch_one(pool).await?)
}

pub async fn count_since(pool: &PgPool, operation_type: &str, since: OffsetDateTime) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        r#"/* postgres */ select count(*) as "count!" from t_audit_log where operation_type = $1 and timestamp >= $2"#,
        operation_type,
        UtcInstant(since) as _
    )
    .fetch_one(pool)
    .await?)
}

/// `= any($2)`: PostgreSQL compares by the column's deterministic collation, as Hibernate's expanded `in` does, so
/// one statement serves every batch length.
pub async fn resources_named(pool: &PgPool, operation_type: &str, ids: &[String]) -> Result<Vec<String>, DbError> {
    Ok(sqlx::query_scalar!(
        "/* postgres */ select distinct resource_id from t_audit_log where operation_type = $1 and resource_id = any($2)",
        operation_type,
        ids
    )
    .fetch_all(pool)
    .await?)
}

pub async fn distinct_operation_types(pool: &PgPool) -> Result<Vec<String>, DbError> {
    Ok(sqlx::query_scalar!(
        "/* postgres */ select distinct operation_type from t_audit_log order by operation_type asc"
    )
    .fetch_all(pool)
    .await?)
}

pub async fn filtered(pool: &PgPool, filter: &Filter, limit: i64, offset: i64) -> Result<(Vec<Row>, i64), DbError> {
    let page = sqlx::query!(
        r#"/* postgres */ select id as "id: TextUuid", description, operation_type, resource_id,
         timestamp as "timestamp: UtcInstant", user_id, ip_address, user_agent, previous_hash, entry_hash
         from t_audit_log
         where (cast($1 as varchar) is null or operation_type = $1)
         and (cast($2 as varchar) is null or user_id = $2)
         and (cast($3 as varchar) is null or lower(description) like $3 or lower(resource_id) like $3)
         order by timestamp desc, id desc limit $4 offset $5"#,
        filter.operation_type,
        filter.user_id,
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
        r#"/* postgres */ select count(*) as "count!" from t_audit_log
         where (cast($1 as varchar) is null or operation_type = $1)
         and (cast($2 as varchar) is null or user_id = $2)
         and (cast($3 as varchar) is null or lower(description) like $3 or lower(resource_id) like $3)"#,
        filter.operation_type,
        filter.user_id,
        filter.pattern
    )
    .fetch_one(pool)
    .await?;
    Ok((page, total))
}
