//! `t_one_shot_job`'s statements on MySQL, checked against a migrated server while compiling (`super`'s note).

use sqlx::mysql::{MySqlConnection, MySqlPool};
use time::OffsetDateTime;

use super::DbError;

pub async fn claim(conn: &mut MySqlConnection, name: &str, at: OffsetDateTime) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* mysql */ insert into t_one_shot_job (name, ran_at) values (?, ?)", name, at)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn exists(pool: &MySqlPool, name: &str) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!("/* mysql */ select name from t_one_shot_job where name = ?", name)
        .fetch_optional(pool)
        .await?
        .is_some())
}
