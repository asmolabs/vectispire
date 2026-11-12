//! `t_sign_in_client` (V101) — `SignInClientRepository`: the clients each account has signed in from, which the
//! account's sign-in budget across every client does not refuse. One row per account and client bucket, keyed by the
//! digest of the two, so the address itself is not stored here.

use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_db::types::to_microseconds;

use crate::persistence::model::StoreError;

/// `existsByClientKeyAndLastSignedInAtAfter`: strictly after `after`.
pub(super) async fn exists_after(db: &Db, key: &str, after: OffsetDateTime) -> Result<bool, StoreError> {
    let after = to_microseconds(after);
    let found = match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_scalar!(
                r#"/* mysql */ select count(*) as "n!: i64" from t_sign_in_client
                where client_key = ? and last_signed_in_at > ?"#,
                key,
                after
            )
            .fetch_one(pool)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_scalar!(
                r#"/* postgres */ select count(*) as "n!" from t_sign_in_client
                where client_key = $1 and last_signed_in_at > $2"#,
                key,
                after
            )
            .fetch_one(pool)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    };
    Ok(found > 0)
}

/// `touch`: a known client refreshed in one statement, the common case — 0 when the client is new to the account.
pub(super) async fn touch(db: &Db, key: &str, at: OffsetDateTime) -> Result<u64, StoreError> {
    let at = to_microseconds(at);
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!("/* mysql */ update t_sign_in_client set last_signed_in_at = ? where client_key = ?", at, key)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!(
            "/* postgres */ update t_sign_in_client set last_signed_in_at = $1 where client_key = $2",
            at,
            key
        )
        .execute(pool)
        .await?
        .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `save(new SignInClientEntity)`: a bare insert, which the primary key refuses when a concurrent sign-in inserted the
/// same client first — the same record, and the caller swallows the refusal.
pub(super) async fn insert(db: &Db, key: &str, account_id: i64, at: OffsetDateTime) -> Result<(), StoreError> {
    let at = to_microseconds(at);
    match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!(
                "/* mysql */ insert into t_sign_in_client (client_key, account_id, last_signed_in_at) values (?, ?, ?)",
                key,
                account_id,
                at
            )
            .execute(pool)
            .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!(
                "/* postgres */ insert into t_sign_in_client (client_key, account_id, last_signed_in_at) \
                 values ($1, $2, $3)",
                key,
                account_id,
                at
            )
            .execute(pool)
            .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    }
    Ok(())
}

/// `deleteBefore`: the clients that have not signed in for the retention — the hourly purge.
pub(super) async fn delete_before(db: &Db, cutoff: OffsetDateTime) -> Result<u64, StoreError> {
    let cutoff = to_microseconds(cutoff);
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_sign_in_client where last_signed_in_at < ?", cutoff)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!("/* postgres */ delete from t_sign_in_client where last_signed_in_at < $1", cutoff)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}
