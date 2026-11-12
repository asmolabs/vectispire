//! A database of its own on each engine, migrated by `vectispire-migrate` — the runner proven against the real
//! Flyway 12.4 in both directions (its `tests/oracle.rs`), so the schema is the one the Java control plane builds.
//!
//! The database is `vectispire_cp_db::testing`'s: in a throwaway container, or on the shared server
//! `VECTISPIRE_TEST_MYSQL_URL` / `VECTISPIRE_TEST_POSTGRES_URL` names (see that module).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use time::OffsetDateTime;
use vectispire_cp_access::SessionsAndKeys;
use vectispire_cp_access::accounts::{RevokedKey, SessionHash, StoreError};
use vectispire_cp_db::{Db, Tx};

#[allow(unused_imports)] // not every suite of the crate reaches a database
pub use vectispire_cp_db::testing::TestDatabase as Migrated;

/// A statement as the server's administrator — what the test arranges behind the pool's back.
pub trait Sql {
    fn sql(&self, statement: &str) -> String;
}

impl Sql for Migrated {
    fn sql(&self, statement: &str) -> String {
        self.sql_as_admin(statement)
    }
}

/// `t_session` and `t_api_key` as `SessionRepository` and `ApiKeyRepository` write them — the credentials task's
/// rows, written here by plain SQL so that the account transactions are proven to commit and roll back with them.
#[derive(Debug, Clone, Copy)]
pub struct RawCredentials;

impl SessionsAndKeys for RawCredentials {
    async fn delete_sessions(&self, tx: &mut Tx, user_id: i64) -> Result<(), StoreError> {
        match tx {
            Tx::MySql(tx) => {
                sqlx::query("delete from t_session where user_id = ?").bind(user_id).execute(&mut **tx).await.map(drop)
            }
            Tx::PostgreSql(tx) => {
                sqlx::query("delete from t_session where user_id = $1").bind(user_id).execute(&mut **tx).await.map(drop)
            }
        }
        .map_err(|error| StoreError(Box::new(error)))
    }

    async fn delete_sessions_except(&self, tx: &mut Tx, user_id: i64, keep: &SessionHash) -> Result<(), StoreError> {
        match tx {
            Tx::MySql(tx) => sqlx::query("delete from t_session where user_id = ? and token_hash <> ?")
                .bind(user_id)
                .bind(&keep.0)
                .execute(&mut **tx)
                .await
                .map(drop),
            Tx::PostgreSql(tx) => sqlx::query("delete from t_session where user_id = $1 and token_hash <> $2")
                .bind(user_id)
                .bind(&keep.0)
                .execute(&mut **tx)
                .await
                .map(drop),
        }
        .map_err(|error| StoreError(Box::new(error)))
    }

    async fn revoke_owned_keys(&self, _tx: &mut Tx, _user_id: i64) -> Result<Vec<RevokedKey>, StoreError> {
        Ok(Vec::new())
    }

    async fn count_active_by_user(&self, db: &Db, at: OffsetDateTime) -> Result<HashMap<i64, u64>, StoreError> {
        let at = vectispire_cp_db::types::UtcInstant(at);
        let rows: Vec<(i64, i64)> = match db {
            Db::MySql(pool) => {
                sqlx::query_as("select user_id, count(token_hash) from t_session where expires_at > ? group by user_id")
                    .bind(at)
                    .fetch_all(pool)
                    .await
            }
            Db::PostgreSql(pool) => {
                sqlx::query_as(
                    "select user_id, count(token_hash) from t_session where expires_at > $1 group by user_id",
                )
                .bind(at)
                .fetch_all(pool)
                .await
            }
        }
        .map_err(|error| StoreError(Box::new(error)))?;
        Ok(rows.into_iter().map(|(user, count)| (user, u64::try_from(count).unwrap_or(0))).collect())
    }
}
