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

type Tuple = (String, i64, OffsetDateTime, OffsetDateTime, OffsetDateTime, Option<String>, Option<String>);

fn row_of(tuple: Tuple) -> SessionRow {
    let (token_hash, user_id, created_at, last_seen_at, expires_at, user_agent, ip_address) = tuple;
    SessionRow { token_hash, user_id, created_at, last_seen_at, expires_at, user_agent, ip_address }
}

/// `findById(hash)`.
pub(crate) async fn find(db: &Db, token_hash: &str) -> Result<Option<SessionRow>, StoreError> {
    let found: Option<Tuple> =
        match db {
            Db::MySql(pool) => sqlx::query_as(
                "/* mysql */ select token_hash, user_id, created_at, last_seen_at, expires_at, user_agent, ip_address \
                 from t_session where token_hash = ?",
            )
            .bind(token_hash)
            .fetch_optional(pool)
            .await?,
            Db::PostgreSql(pool) => {
                sqlx::query_as(
                    "/* postgres */ select token_hash, user_id, created_at, last_seen_at, expires_at, user_agent, \
                 ip_address from t_session where token_hash = $1",
                )
                .bind(token_hash)
                .fetch_optional(pool)
                .await?
            }
        };
    Ok(found.map(row_of))
}

/// `save(new SessionEntity)`: the row as opened.
pub(crate) async fn insert(db: &Db, row: &SessionRow) -> Result<(), StoreError> {
    match db {
        Db::MySql(pool) => {
            sqlx::query(
                "/* mysql */ insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at, \
                 user_agent, ip_address) values (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&row.token_hash)
            .bind(row.user_id)
            .bind(to_microseconds(row.created_at))
            .bind(to_microseconds(row.last_seen_at))
            .bind(to_microseconds(row.expires_at))
            .bind(&row.user_agent)
            .bind(&row.ip_address)
            .execute(pool)
            .await?;
        }
        Db::PostgreSql(pool) => {
            sqlx::query(
                "/* postgres */ insert into t_session (token_hash, user_id, created_at, last_seen_at, expires_at, \
                 user_agent, ip_address) values ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&row.token_hash)
            .bind(row.user_id)
            .bind(to_microseconds(row.created_at))
            .bind(to_microseconds(row.last_seen_at))
            .bind(to_microseconds(row.expires_at))
            .bind(&row.user_agent)
            .bind(&row.ip_address)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// The activity a resolution records — what `save(session)` changed of the row.
pub(crate) async fn touch(db: &Db, token_hash: &str, last_seen_at: OffsetDateTime) -> Result<(), StoreError> {
    let at = to_microseconds(last_seen_at);
    match db {
        Db::MySql(pool) => {
            sqlx::query("/* mysql */ update t_session set last_seen_at = ? where token_hash = ?")
                .bind(at)
                .bind(token_hash)
                .execute(pool)
                .await?;
        }
        Db::PostgreSql(pool) => {
            sqlx::query("/* postgres */ update t_session set last_seen_at = $1 where token_hash = $2")
                .bind(at)
                .bind(token_hash)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

/// `deleteById` and `consume`: how many rows went — of two callers consuming one row, one deletes it and the other
/// deletes nothing, which is what makes a hand-off single-use.
pub(crate) async fn delete(db: &Db, token_hash: &str) -> Result<u64, StoreError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query("/* mysql */ delete from t_session where token_hash = ?")
            .bind(token_hash)
            .execute(pool)
            .await?
            .rows_affected(),
        Db::PostgreSql(pool) => sqlx::query("/* postgres */ delete from t_session where token_hash = $1")
            .bind(token_hash)
            .execute(pool)
            .await?
            .rows_affected(),
    })
}

/// `deleteByUserId`: every session of an account.
pub(crate) async fn delete_by_user(db: &Db, user_id: i64) -> Result<u64, StoreError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query("/* mysql */ delete from t_session where user_id = ?")
            .bind(user_id)
            .execute(pool)
            .await?
            .rows_affected(),
        Db::PostgreSql(pool) => sqlx::query("/* postgres */ delete from t_session where user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await?
            .rows_affected(),
    })
}

/// `deleteByUserIdExcept`: an account's other sessions, keeping the one making the request.
pub(crate) async fn delete_by_user_except(db: &Db, user_id: i64, keep: &str) -> Result<u64, StoreError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query("/* mysql */ delete from t_session where user_id = ? and token_hash <> ?")
            .bind(user_id)
            .bind(keep)
            .execute(pool)
            .await?
            .rows_affected(),
        Db::PostgreSql(pool) => {
            sqlx::query("/* postgres */ delete from t_session where user_id = $1 and token_hash <> $2")
                .bind(user_id)
                .bind(keep)
                .execute(pool)
                .await?
                .rows_affected()
        }
    })
}

/// `deleteExpired`: the rows whose absolute lifetime has passed — the maintenance purge.
pub(crate) async fn delete_expired(db: &Db, as_of: OffsetDateTime) -> Result<u64, StoreError> {
    let as_of = to_microseconds(as_of);
    Ok(match db {
        Db::MySql(pool) => sqlx::query("/* mysql */ delete from t_session where expires_at < ?")
            .bind(as_of)
            .execute(pool)
            .await?
            .rows_affected(),
        Db::PostgreSql(pool) => sqlx::query("/* postgres */ delete from t_session where expires_at < $1")
            .bind(as_of)
            .execute(pool)
            .await?
            .rows_affected(),
    })
}

/// `countActiveByUser`: live sessions per account, on the absolute expiry alone (the idle window is re-evaluated
/// on every request; applying it to a count would make the number change while nobody did anything).
pub(crate) async fn count_active_by_user(db: &Db, as_of: OffsetDateTime) -> Result<Vec<(i64, i64)>, StoreError> {
    let as_of = to_microseconds(as_of);
    let rows: Vec<(i64, i64)> =
        match db {
            Db::MySql(pool) => sqlx::query_as(
                "/* mysql */ select user_id, count(token_hash) from t_session where expires_at > ? group by user_id",
            )
            .bind(as_of)
            .fetch_all(pool)
            .await?,
            Db::PostgreSql(pool) => {
                sqlx::query_as(
                    "/* postgres */ select user_id, count(token_hash) from t_session where expires_at > $1 \
                 group by user_id",
                )
                .bind(as_of)
                .fetch_all(pool)
                .await?
            }
        };
    Ok(rows)
}
