//! `t_setting`'s statements on PostgreSQL, checked against a migrated server while compiling (`super`'s note).

use sqlx::postgres::PgPool;
use sqlx::{Executor, Postgres};
use time::OffsetDateTime;
use vectispire_cp_db::types::UtcInstant;

use super::{DbError, IntegrationRow};

pub async fn all(pool: &PgPool) -> Result<Vec<(String, Option<String>)>, DbError> {
    Ok(sqlx::query!("/* postgres */ select key, value from t_setting")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| (row.key, row.value))
        .collect())
}

/// On a pool or in a transaction: the store reads both ways.
pub async fn find<'c>(
    executor: impl Executor<'c, Database = Postgres>,
    key: &str,
) -> Result<Option<Option<String>>, DbError> {
    Ok(sqlx::query_scalar!("/* postgres */ select value from t_setting where key = $1", key)
        .fetch_optional(executor)
        .await?)
}

/// On a pool or in a transaction: the store calls it both ways.
pub async fn insert<'c>(
    executor: impl Executor<'c, Database = Postgres>,
    key: &str,
    value: Option<&str>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* postgres */ insert into t_setting (key, value) values ($1, $2)", key, value)
        .execute(executor)
        .await?
        .rows_affected())
}

pub async fn update_value(conn: &mut sqlx::PgConnection, key: &str, value: Option<&str>) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* postgres */ update t_setting set value = $1 where key = $2", value, key)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn replace_value(
    conn: &mut sqlx::PgConnection,
    key: &str,
    expected: &str,
    value: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_setting set value = $1 where key = $2 and value = $3",
        value,
        key,
        expected
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn delete(conn: &mut sqlx::PgConnection, key: &str) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* postgres */ delete from t_setting where key = $1", key).execute(conn).await?.rows_affected())
}

// ── t_integration ──

pub async fn integrations(pool: &PgPool) -> Result<Vec<IntegrationRow>, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ select integration_key, enabled, updated_at as "updated_at: UtcInstant", updated_by
           from t_integration"#
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
    executor: impl Executor<'c, Database = Postgres>,
    key: &str,
) -> Result<Option<IntegrationRow>, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ select integration_key, enabled, updated_at as "updated_at: UtcInstant", updated_by
           from t_integration where integration_key = $1"#,
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

pub async fn lock_for_switch(conn: &mut sqlx::PgConnection, key: &str) -> Result<Option<bool>, DbError> {
    Ok(sqlx::query_scalar!(
        "/* postgres */ select enabled from t_integration where integration_key = $1 for update",
        key
    )
    .fetch_optional(conn)
    .await?)
}

pub async fn lock_for_use(conn: &mut sqlx::PgConnection, key: &str) -> Result<Option<bool>, DbError> {
    Ok(sqlx::query_scalar!(
        "/* postgres */ select enabled from t_integration where integration_key = $1 for share",
        key
    )
    .fetch_optional(conn)
    .await?)
}

pub async fn switch_integration(
    conn: &mut sqlx::PgConnection,
    key: &str,
    enabled: bool,
    at: OffsetDateTime,
    by: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_integration set enabled = $1, updated_at = $2, updated_by = $3 \
         where integration_key = $4 and enabled <> $1",
        enabled,
        UtcInstant(at) as _,
        by,
        key
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn insert_integration(
    conn: &mut sqlx::PgConnection,
    key: &str,
    at: OffsetDateTime,
    by: &str,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ insert into t_integration (integration_key, enabled, updated_at, updated_by) \
         values ($1, true, $2, $3)",
        key,
        UtcInstant(at) as _,
        by
    )
    .execute(conn)
    .await?
    .rows_affected())
}
