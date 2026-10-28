//! `t_api_key` — `ApiKeyRepository`. The key's hash is Argon2id over the whole key; its first twelve characters are
//! stored in the clear beside it, to narrow a lookup.

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::Db;
use vectispire_cp_db::types::to_microseconds;

use super::{StoreError, uuid_of};

/// A row of `t_api_key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyRow {
    pub id: Uuid,
    pub name: String,
    pub key_hash: String,
    pub prefix: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub scopes: String,
    pub target_kind: Option<String>,
    pub target_id: Option<i64>,
    pub expires_at: Option<OffsetDateTime>,
    pub owner_user_id: Option<i64>,
}

/// A row as stored: the id is `char(36)` text, made a [`Uuid`] by [`Stored::row`].
struct Stored {
    id: String,
    name: String,
    key_hash: String,
    prefix: Option<String>,
    created_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
    scopes: String,
    target_kind: Option<String>,
    target_id: Option<i64>,
    expires_at: Option<OffsetDateTime>,
    owner_user_id: Option<i64>,
}

impl Stored {
    fn row(self) -> Result<KeyRow, StoreError> {
        Ok(KeyRow {
            id: uuid_of(&self.id)?,
            name: self.name,
            key_hash: self.key_hash,
            prefix: self.prefix,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
            scopes: self.scopes,
            target_kind: self.target_kind,
            target_id: self.target_id,
            expires_at: self.expires_at,
            owner_user_id: self.owner_user_id,
        })
    }
}

/// `findByPrefix`: the candidates a presented key could be. The order is the engine's, as Java's is.
pub(crate) async fn find_by_prefix(db: &Db, prefix: &str) -> Result<Vec<KeyRow>, StoreError> {
    // MySQL's `datetime(6)` would be read as a zone-less `PrimitiveDateTime`; Hibernate stores UTC there.
    let stored = match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_as!(
                Stored,
                r#"/* mysql */ select id, name, key_hash, prefix, created_at as "created_at: _",
                last_used_at as "last_used_at: _", scopes, target_kind, target_id, expires_at as "expires_at: _",
                owner_user_id from t_api_key where prefix = ?"#,
                prefix
            )
            .fetch_all(pool)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_as!(
                Stored,
                "/* postgres */ select id, name, key_hash, prefix, created_at, last_used_at, scopes, target_kind, \
                 target_id, expires_at, owner_user_id from t_api_key where prefix = $1",
                prefix
            )
            .fetch_all(pool)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    };
    stored.into_iter().map(Stored::row).collect()
}

/// `findById`.
pub(crate) async fn find(db: &Db, id: Uuid) -> Result<Option<KeyRow>, StoreError> {
    let id = id.as_hyphenated().to_string();
    // MySQL's `datetime(6)` would be read as a zone-less `PrimitiveDateTime`; Hibernate stores UTC there.
    let stored = match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_as!(
                Stored,
                r#"/* mysql */ select id, name, key_hash, prefix, created_at as "created_at: _",
                last_used_at as "last_used_at: _", scopes, target_kind, target_id, expires_at as "expires_at: _",
                owner_user_id from t_api_key where id = ?"#,
                id
            )
            .fetch_optional(pool)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_as!(
                Stored,
                "/* postgres */ select id, name, key_hash, prefix, created_at, last_used_at, scopes, target_kind, \
                 target_id, expires_at, owner_user_id from t_api_key where id = $1",
                id
            )
            .fetch_optional(pool)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    };
    stored.map(Stored::row).transpose()
}

/// `markUsed`: the only trace that lets an operator spot a key issued for a use that never happened.
pub(crate) async fn mark_used(db: &Db, id: Uuid, at: OffsetDateTime) -> Result<u64, StoreError> {
    let id = id.as_hyphenated().to_string();
    let at = to_microseconds(at);
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ update t_api_key set last_used_at = ? where id = ?", at, id)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!("/* postgres */ update t_api_key set last_used_at = $1 where id = $2", at, id)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}

/// `save(new ApiKeyEntity)`.
pub(crate) async fn insert(db: &Db, row: &KeyRow) -> Result<(), StoreError> {
    let id = row.id.as_hyphenated().to_string();
    let created = to_microseconds(row.created_at);
    let used = row.last_used_at.map(to_microseconds);
    let expires = row.expires_at.map(to_microseconds);
    match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!(
                "/* mysql */ insert into t_api_key (id, name, key_hash, prefix, created_at, last_used_at, scopes, \
                 target_kind, target_id, expires_at, owner_user_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                id,
                row.name,
                row.key_hash,
                row.prefix,
                created,
                used,
                row.scopes,
                row.target_kind,
                row.target_id,
                expires,
                row.owner_user_id
            )
            .execute(pool)
            .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!(
                "/* postgres */ insert into t_api_key (id, name, key_hash, prefix, created_at, last_used_at, scopes, \
                 target_kind, target_id, expires_at, owner_user_id) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                id,
                row.name,
                row.key_hash,
                row.prefix,
                created,
                used,
                row.scopes,
                row.target_kind,
                row.target_id,
                expires,
                row.owner_user_id
            )
            .execute(pool)
            .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    }
    Ok(())
}

/// `deleteById`: revoking deletes the row — a "disabled" key that something could re-enable by accident would be
/// worse than an absent one. The audit trail keeps the record.
pub(crate) async fn delete(db: &Db, id: Uuid) -> Result<u64, StoreError> {
    let id = id.as_hyphenated().to_string();
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query!("/* mysql */ delete from t_api_key where id = ?", id).execute(pool).await?.rows_affected()
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!("/* postgres */ delete from t_api_key where id = $1", id).execute(pool).await?.rows_affected()
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}

/// `revokeOwnedBy`: every key an account issued — when the account goes, the keys that borrow its authority go too.
pub(crate) async fn delete_owned_by(db: &Db, owner: i64) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_api_key where owner_user_id = ?", owner)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!("/* postgres */ delete from t_api_key where owner_user_id = $1", owner)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}
