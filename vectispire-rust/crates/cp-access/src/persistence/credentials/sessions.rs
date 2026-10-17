//! `t_session` — `SessionRepository`. The primary key is the token's SHA-256, never the token.

use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_db::types::to_microseconds;

use super::StoreError;

/// A row of `t_session`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionRow {
    pub token_hash: String,
    pub user_id: i64,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

/// `findById(hash)`.
pub(crate) async fn find(db: &Db, token_hash: &str) -> Result<Option<SessionRow>, StoreError> {
    // MySQL's `datetime(6)` would be read as a zone-less `PrimitiveDateTime`; Hibernate stores UTC there, which the
    // field's `OffsetDateTime` says.
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_as!(
                SessionRow,
                r#"/* mysql */ select token_hash, user_id, created_at as "created_at: _",
                last_seen_at as "last_seen_at: _", expires_at as "expires_at: _", user_agent, ip_address
                from t_session where token_hash = ?"#,
                token_hash
            )
            .fetch_optional(pool)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_as!(
                SessionRow,
                "/* postgres */ select token_hash, user_id, created_at, last_seen_at, expires_at, user_agent, \
                 ip_address from t_session where token_hash = $1",
                token_hash
            )
            .fetch_optional(pool)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}

/// `save(new SessionEntity)`: the row as opened.
pub(crate) async fn insert(db: &Db, row: &SessionRow) -> Result<(), StoreError> {
    let (created, seen, expires) =
        (to_microseconds(row.created_at), to_microseconds(row.last_seen_at), to_microseconds(row.expires_at));
    match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!(
                "/* mysql */ insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at, \
                 user_agent, ip_address) values (?, ?, ?, ?, ?, ?, ?)",
                row.token_hash,
                row.user_id,
                created,
                seen,
                expires,
                row.user_agent,
                row.ip_address
            )
            .execute(pool)
            .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!(
                "/* postgres */ insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at, \
                 user_agent, ip_address) values ($1, $2, $3, $4, $5, $6, $7)",
                row.token_hash,
                row.user_id,
                created,
                seen,
                expires,
                row.user_agent,
                row.ip_address
            )
            .execute(pool)
            .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    }
    Ok(())
}

/// The activity a resolution records — what `save(session)` changed of the row.
pub(crate) async fn touch(db: &Db, token_hash: &str, last_seen_at: OffsetDateTime) -> Result<(), StoreError> {
    let at = to_microseconds(last_seen_at);
    match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!("/* mysql */ update t_session set last_seen_at = ? where token_hash = ?", at, token_hash)
                .execute(pool)
                .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!("/* postgres */ update t_session set last_seen_at = $1 where token_hash = $2", at, token_hash)
                .execute(pool)
                .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    }
    Ok(())
}

/// `deleteById` and `consume`: how many rows went — of two callers consuming one row, one deletes it and the other
/// deletes nothing, which is what makes a hand-off single-use.
pub(crate) async fn delete(db: &Db, token_hash: &str) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_session where token_hash = ?", token_hash)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!("/* postgres */ delete from t_session where token_hash = $1", token_hash)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}

/// `deleteByUserId`: every session of an account.
pub(crate) async fn delete_by_user(db: &Db, user_id: i64) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_session where user_id = ?", user_id)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!("/* postgres */ delete from t_session where user_id = $1", user_id)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}

/// `deleteByUserIdExcept`: an account's other sessions, keeping the one making the request.
pub(crate) async fn delete_by_user_except(db: &Db, user_id: i64, keep: &str) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!("/* mysql */ delete from t_session where user_id = ? and token_hash <> ?", user_id, keep)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!("/* postgres */ delete from t_session where user_id = $1 and token_hash <> $2", user_id, keep)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}

/// `deleteExpired`: the rows whose absolute lifetime has passed — the maintenance purge.
pub(crate) async fn delete_expired(db: &Db, as_of: OffsetDateTime) -> Result<u64, StoreError> {
    let as_of = to_microseconds(as_of);
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_session where expires_at < ?", as_of)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!("/* postgres */ delete from t_session where expires_at < $1", as_of)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}

/// `countActiveByUser`: live sessions per account, on the absolute expiry alone (the idle window is re-evaluated
/// on every request; applying it to a count would make the number change while nobody did anything).
pub(crate) async fn count_active_by_user(db: &Db, as_of: OffsetDateTime) -> Result<Vec<(i64, i64)>, StoreError> {
    let as_of = to_microseconds(as_of);
    // PostgreSQL describes an aggregate as possibly null; a `count` never is.
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!(
            r#"/* mysql */ select user_id, count(token_hash) as "sessions!: i64" from t_session where expires_at > ?
            group by user_id"#,
            as_of
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| (row.user_id, row.sessions))
        .collect(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!(
            r#"/* postgres */ select user_id, count(token_hash) as "sessions!: i64" from t_session where expires_at > $1
            group by user_id"#,
            as_of
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| (row.user_id, row.sessions))
        .collect(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}
