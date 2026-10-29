//! `t_rate_window` — `RateWindowRepository`: one row per limited subject and fixed window, counted by every instance.

use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_db::types::to_microseconds;

use crate::persistence::model::StoreError;

/// `increment`: 0 when the window has no row yet.
pub(super) async fn increment(db: &Db, key: &str) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!("/* mysql */ update t_rate_window set hits = hits + 1 where window_key = ?", key)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!("/* postgres */ update t_rate_window set hits = hits + 1 where window_key = $1", key)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `insertFirst`: a bare insert, never a merge — the primary key refuses the second instance's, which then
/// increments. On its own connection, so that on PostgreSQL the refusal poisons no transaction the increment needs.
pub(super) async fn insert_first(db: &Db, key: &str, expires_at: OffsetDateTime) -> Result<(), StoreError> {
    let expires = to_microseconds(expires_at);
    match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!(
                "/* mysql */ insert into t_rate_window (window_key, hits, expires_at) values (?, 1, ?)",
                key,
                expires
            )
            .execute(pool)
            .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!(
                "/* postgres */ insert into t_rate_window (window_key, hits, expires_at) values ($1, 1, $2)",
                key,
                expires
            )
            .execute(pool)
            .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    }
    Ok(())
}

/// `hitsOf`.
pub(super) async fn hits_of(db: &Db, key: &str) -> Result<Option<i32>, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_scalar!("/* mysql */ select hits from t_rate_window where window_key = ?", key)
                .fetch_optional(pool)
                .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_scalar!("/* postgres */ select hits from t_rate_window where window_key = $1", key)
                .fetch_optional(pool)
                .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `deleteExpired`.
pub(super) async fn delete_expired(db: &Db, now: OffsetDateTime) -> Result<u64, StoreError> {
    let now = to_microseconds(now);
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_rate_window where expires_at < ?", now)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!("/* postgres */ delete from t_rate_window where expires_at < $1", now)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `deleteByKeyPrefix`: `like`, the pattern as the caller spells it.
pub(super) async fn delete_by_key_prefix(db: &Db, pattern: &str) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_rate_window where window_key like ?", pattern)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!("/* postgres */ delete from t_rate_window where window_key like $1", pattern)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}
