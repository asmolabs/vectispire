//! `t_setting`'s statements on MySQL, checked against a migrated server while compiling (`super`'s note). The
//! key column is quoted: `key` is reserved here.

use sqlx::mysql::MySqlPool;
use sqlx::{Executor, MySql};
use time::OffsetDateTime;
use vectispire_cp_db::types::UtcInstant;

use super::{DbError, IntegrationRow};

pub async fn all(pool: &MySqlPool) -> Result<Vec<(String, Option<String>)>, DbError> {
    Ok(sqlx::query!("/* mysql */ select `key`, value from t_setting")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| (row.key, row.value))
        .collect())
}

/// On a pool or in a transaction: the store reads both ways.
pub async fn find<'c>(
    executor: impl Executor<'c, Database = MySql>,
    key: &str,
) -> Result<Option<Option<String>>, DbError> {
    Ok(sqlx::query_scalar!("/* mysql */ select value from t_setting where `key` = ?", key)
        .fetch_optional(executor)
        .await?)
}

/// On a pool or in a transaction: the store calls it both ways.
pub async fn insert<'c>(
    executor: impl Executor<'c, Database = MySql>,
    key: &str,
    value: Option<&str>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* mysql */ insert into t_setting (`key`, value) values (?, ?)", key, value)
        .execute(executor)
        .await?
        .rows_affected())
}

pub async fn update_value(conn: &mut sqlx::MySqlConnection, key: &str, value: Option<&str>) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* mysql */ update t_setting set value = ? where `key` = ?", value, key)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn replace_value(
    conn: &mut sqlx::MySqlConnection,
    key: &str,
    expected: &str,
    value: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* mysql */ update t_setting set value = ? where `key` = ? and value = ?", value, key, expected)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn delete(conn: &mut sqlx::MySqlConnection, key: &str) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* mysql */ delete from t_setting where `key` = ?", key).execute(conn).await?.rows_affected())
}

// ── t_integration ──

pub async fn integrations(pool: &MySqlPool) -> Result<Vec<IntegrationRow>, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ select integration_key, enabled as `enabled: bool`, updated_at as `updated_at: UtcInstant`, \
         updated_by from t_integration"
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| IntegrationRow {
        key: row.integration_key,
        enabled: row.enabled,
        updated_at: row.updated_at.map(|at| at.0),
        updated_by: row.updated_by,
    })
    .collect())
}

/// On a pool or in a transaction.
pub async fn integration<'c>(
    executor: impl Executor<'c, Database = MySql>,
    key: &str,
) -> Result<Option<IntegrationRow>, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ select integration_key, enabled as `enabled: bool`, updated_at as `updated_at: UtcInstant`, \
         updated_by from t_integration where integration_key = ?",
        key
    )
    .fetch_optional(executor)
    .await?
    .map(|row| IntegrationRow {
        key: row.integration_key,
        enabled: row.enabled,
        updated_at: row.updated_at.map(|at| at.0),
        updated_by: row.updated_by,
    }))
}

pub async fn lock_for_switch(conn: &mut sqlx::MySqlConnection, key: &str) -> Result<Option<bool>, DbError> {
    Ok(sqlx::query_scalar!(
        "/* mysql */ select enabled as `enabled: bool` from t_integration where integration_key = ? for update",
        key
    )
    .fetch_optional(conn)
    .await?)
}

pub async fn lock_for_use(conn: &mut sqlx::MySqlConnection, key: &str) -> Result<Option<bool>, DbError> {
    Ok(sqlx::query_scalar!(
        "/* mysql */ select enabled as `enabled: bool` from t_integration where integration_key = ? for share",
        key
    )
    .fetch_optional(conn)
    .await?)
}

pub async fn switch_integration(
    conn: &mut sqlx::MySqlConnection,
    key: &str,
    enabled: bool,
    at: OffsetDateTime,
    by: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_integration set enabled = ?, updated_at = ?, updated_by = ? \
         where integration_key = ? and enabled <> ?",
        enabled,
        UtcInstant(at),
        by,
        key,
        enabled
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn insert_integration(
    conn: &mut sqlx::MySqlConnection,
    key: &str,
    at: OffsetDateTime,
    by: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ insert into t_integration (integration_key, enabled, updated_at, updated_by) values (?, true, ?, ?)",
        key,
        UtcInstant(at),
        by
    )
    .execute(conn)
    .await?
    .rows_affected())
}
