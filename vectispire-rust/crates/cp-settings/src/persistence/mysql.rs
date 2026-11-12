//! `t_setting`'s statements on MySQL, checked against a migrated server while compiling (`super`'s note). The
//! key column is quoted: `key` is reserved here.

use sqlx::mysql::MySqlPool;
use sqlx::{Executor, MySql};

use super::DbError;

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
