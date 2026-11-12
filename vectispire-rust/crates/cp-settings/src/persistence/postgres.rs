//! `t_setting`'s statements on PostgreSQL, checked against a migrated server while compiling (`super`'s note).

use sqlx::postgres::PgPool;
use sqlx::{Executor, Postgres};

use super::DbError;

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
