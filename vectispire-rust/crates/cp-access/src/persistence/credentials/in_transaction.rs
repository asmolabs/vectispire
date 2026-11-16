//! [`SessionsAndKeys`] on the credential tables: what an account transaction does to the account's sessions and keys,
//! **inside the transaction it is given** — `AccountAdminService` saves the row and closes the sessions in one, so a
//! failure between them cannot leave a reset password beside the session it was meant to close.
//!
//! The statements are the pool's own (`sessions.rs`, `api_keys.rs`) run on the transaction's connection: the same text,
//! so the same checked cache entry.

use std::collections::HashMap;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Tx};

use super::{sessions, uuid_of};
use crate::persistence::model::{RevokedKey, SessionHash, StoreError};
use crate::persistence::users::SessionsAndKeys;

/// The credential tables, as the account transactions write them.
#[derive(Clone, Copy, Debug, Default)]
pub struct CredentialTables;

fn failed(error: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError(Box::new(error))
}

impl SessionsAndKeys for CredentialTables {
    async fn delete_sessions(&self, tx: &mut Tx, user_id: i64) -> Result<(), StoreError> {
        match tx {
            #[cfg(feature = "mysql-queries")]
            Tx::MySql(tx) => {
                sqlx::query!("/* mysql */ delete from t_session where user_id = ?", user_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(failed)?;
            }
            #[cfg(feature = "postgres-queries")]
            Tx::PostgreSql(tx) => {
                sqlx::query!("/* postgres */ delete from t_session where user_id = $1", user_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(failed)?;
            }
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => return Err(StoreError("this build carries no statement for this engine".into())),
        }
        Ok(())
    }

    async fn delete_sessions_except(&self, tx: &mut Tx, user_id: i64, keep: &SessionHash) -> Result<(), StoreError> {
        let keep = keep.0.as_str();
        match tx {
            #[cfg(feature = "mysql-queries")]
            Tx::MySql(tx) => {
                sqlx::query!("/* mysql */ delete from t_session where user_id = ? and token_hash <> ?", user_id, keep)
                    .execute(&mut **tx)
                    .await
                    .map_err(failed)?;
            }
            #[cfg(feature = "postgres-queries")]
            Tx::PostgreSql(tx) => {
                sqlx::query!(
                    "/* postgres */ delete from t_session where user_id = $1 and token_hash <> $2",
                    user_id,
                    keep
                )
                .execute(&mut **tx)
                .await
                .map_err(failed)?;
            }
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => return Err(StoreError("this build carries no statement for this engine".into())),
        }
        Ok(())
    }

    /// `revokeOwnedBy`: the keys the account owns, in the order they were issued (`findByOwnerUserIdOrderByCreatedAtAscIdAsc`),
    /// read so that each is audited under its own id, then deleted.
    async fn revoke_owned_keys(&self, tx: &mut Tx, user_id: i64) -> Result<Vec<RevokedKey>, StoreError> {
        let owned: Vec<(String, String)> = match tx {
            #[cfg(feature = "mysql-queries")]
            Tx::MySql(tx) => {
                let rows = sqlx::query!(
                    "/* mysql */ select id, name from t_api_key where owner_user_id = ? order by created_at, id",
                    user_id
                )
                .fetch_all(&mut **tx)
                .await
                .map_err(failed)?;
                sqlx::query!("/* mysql */ delete from t_api_key where owner_user_id = ?", user_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(failed)?;
                rows.into_iter().map(|row| (row.id, row.name)).collect()
            }
            #[cfg(feature = "postgres-queries")]
            Tx::PostgreSql(tx) => {
                let rows = sqlx::query!(
                    "/* postgres */ select id, name from t_api_key where owner_user_id = $1 order by created_at, id",
                    user_id
                )
                .fetch_all(&mut **tx)
                .await
                .map_err(failed)?;
                sqlx::query!("/* postgres */ delete from t_api_key where owner_user_id = $1", user_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(failed)?;
                rows.into_iter().map(|row| (row.id, row.name)).collect()
            }
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => return Err(StoreError("this build carries no statement for this engine".into())),
        };
        owned.into_iter().map(|(id, name)| Ok(RevokedKey { id: uuid_of(&id).map_err(failed)?, name })).collect()
    }

    async fn count_active_by_user(&self, db: &Db, at: OffsetDateTime) -> Result<HashMap<i64, u64>, StoreError> {
        let rows = sessions::count_active_by_user(db, at).await.map_err(failed)?;
        Ok(rows.into_iter().map(|(user, count)| (user, u64::try_from(count).unwrap_or(0))).collect())
    }
}
