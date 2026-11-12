//! `t_mfa_challenge` — `MfaChallengeRepository`. The primary key is the challenge token's SHA-256, never the token.

use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_db::types::to_microseconds;

use super::Challenge;
use crate::persistence::model::StoreError;

/// `findById(tokenHash)`.
pub(super) async fn find(db: &Db, token_hash: &str) -> Result<Option<Challenge>, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_as!(
                Challenge,
                r#"/* mysql */ select token_hash, user_id, expires_at as "expires_at: _", attempts, user_agent,
                ip_address from t_mfa_challenge where token_hash = ?"#,
                token_hash
            )
            .fetch_optional(pool)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_as!(
                Challenge,
                "/* postgres */ select token_hash, user_id, expires_at, attempts, user_agent, ip_address \
                 from t_mfa_challenge where token_hash = $1",
                token_hash
            )
            .fetch_optional(pool)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `save(new MfaChallengeEntity)`.
pub(super) async fn insert(db: &Db, challenge: &Challenge) -> Result<(), StoreError> {
    let expires = to_microseconds(challenge.expires_at);
    match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!(
                "/* mysql */ insert into t_mfa_challenge (token_hash, user_id, expires_at, attempts, user_agent, \
                 ip_address) values (?, ?, ?, ?, ?, ?)",
                challenge.token_hash,
                challenge.user_id,
                expires,
                challenge.attempts,
                challenge.user_agent,
                challenge.ip_address
            )
            .execute(pool)
            .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!(
                "/* postgres */ insert into t_mfa_challenge (token_hash, user_id, expires_at, attempts, user_agent, \
                 ip_address) values ($1, $2, $3, $4, $5, $6)",
                challenge.token_hash,
                challenge.user_id,
                expires,
                challenge.attempts,
                challenge.user_agent,
                challenge.ip_address
            )
            .execute(pool)
            .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    }
    Ok(())
}

/// `countAttempt`: an update rather than a read and a write — two codes at once would otherwise each read 2 and
/// write 3, a challenge that absorbed four guesses believing it had seen three.
pub(super) async fn count_attempt(db: &Db, token_hash: &str) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!(
            "/* mysql */ update t_mfa_challenge set attempts = attempts + 1 where token_hash = ?",
            token_hash
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!(
            "/* postgres */ update t_mfa_challenge set attempts = attempts + 1 where token_hash = $1",
            token_hash
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `discard`.
pub(super) async fn discard(db: &Db, token_hash: &str) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_mfa_challenge where token_hash = ?", token_hash)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!("/* postgres */ delete from t_mfa_challenge where token_hash = $1", token_hash)
                .execute(pool)
                .await?
                .rows_affected()
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
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_mfa_challenge where expires_at < ?", now)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!("/* postgres */ delete from t_mfa_challenge where expires_at < $1", now)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `countByExpiresAtAfter`.
pub(super) async fn count_live(db: &Db, now: OffsetDateTime) -> Result<i64, StoreError> {
    let now = to_microseconds(now);
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_scalar!(
                r#"/* mysql */ select count(*) as "n!: i64" from t_mfa_challenge where expires_at > ?"#,
                now
            )
            .fetch_one(pool)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_scalar!(
                r#"/* postgres */ select count(*) as "n!" from t_mfa_challenge where expires_at > $1"#,
                now
            )
            .fetch_one(pool)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}
