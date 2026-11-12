//! `t_one_shot_job`'s statements on PostgreSQL, checked against a migrated server while compiling (`super`'s note).

use sqlx::postgres::{PgConnection, PgPool};
use time::OffsetDateTime;

use super::DbError;

pub async fn claim(conn: &mut PgConnection, name: &str, at: OffsetDateTime) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* postgres */ insert into t_one_shot_job (name, ran_at) values ($1, $2)", name, at)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn exists(pool: &PgPool, name: &str) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!("/* postgres */ select name from t_one_shot_job where name = $1", name)
        .fetch_optional(pool)
        .await?
        .is_some())
}
