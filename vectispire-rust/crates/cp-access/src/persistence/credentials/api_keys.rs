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

type Tuple = (
    String,
    String,
    String,
    Option<String>,
    OffsetDateTime,
    Option<OffsetDateTime>,
    String,
    Option<String>,
    Option<i64>,
    Option<OffsetDateTime>,
    Option<i64>,
);

fn row_of(tuple: Tuple) -> Result<KeyRow, StoreError> {
    let (id, name, key_hash, prefix, created_at, last_used_at, scopes, target_kind, target_id, expires_at, owner) =
        tuple;
    Ok(KeyRow {
        id: uuid_of(&id)?,
        name,
        key_hash,
        prefix,
        created_at,
        last_used_at,
        scopes,
        target_kind,
        target_id,
        expires_at,
        owner_user_id: owner,
    })
}

/// `findByPrefix`: the candidates a presented key could be. The order is the engine's, as Java's is.
pub(crate) async fn find_by_prefix(db: &Db, prefix: &str) -> Result<Vec<KeyRow>, StoreError> {
    let rows: Vec<Tuple> = match db {
        Db::MySql(pool) => {
            sqlx::query_as(
                "/* mysql */ select id, name, key_hash, prefix, created_at, last_used_at, scopes, target_kind, \
                 target_id, expires_at, owner_user_id from t_api_key where prefix = ?",
            )
            .bind(prefix)
            .fetch_all(pool)
            .await?
        }
        Db::PostgreSql(pool) => {
            sqlx::query_as(
                "/* postgres */ select id, name, key_hash, prefix, created_at, last_used_at, scopes, target_kind, \
                 target_id, expires_at, owner_user_id from t_api_key where prefix = $1",
            )
            .bind(prefix)
            .fetch_all(pool)
            .await?
        }
    };
    rows.into_iter().map(row_of).collect()
}

/// `findById`.
pub(crate) async fn find(db: &Db, id: Uuid) -> Result<Option<KeyRow>, StoreError> {
    let id = id.as_hyphenated().to_string();
    let row: Option<Tuple> = match db {
        Db::MySql(pool) => {
            sqlx::query_as(
                "/* mysql */ select id, name, key_hash, prefix, created_at, last_used_at, scopes, target_kind, \
                 target_id, expires_at, owner_user_id from t_api_key where id = ?",
            )
            .bind(id)
            .fetch_optional(pool)
            .await?
        }
        Db::PostgreSql(pool) => {
            sqlx::query_as(
                "/* postgres */ select id, name, key_hash, prefix, created_at, last_used_at, scopes, target_kind, \
                 target_id, expires_at, owner_user_id from t_api_key where id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await?
        }
    };
    row.map(row_of).transpose()
}

/// `markUsed`: the only trace that lets an operator spot a key issued for a use that never happened.
pub(crate) async fn mark_used(db: &Db, id: Uuid, at: OffsetDateTime) -> Result<u64, StoreError> {
    let id = id.as_hyphenated().to_string();
    let at = to_microseconds(at);
    Ok(match db {
        Db::MySql(pool) => sqlx::query("/* mysql */ update t_api_key set last_used_at = ? where id = ?")
            .bind(at)
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected(),
        Db::PostgreSql(pool) => sqlx::query("/* postgres */ update t_api_key set last_used_at = $1 where id = $2")
            .bind(at)
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected(),
    })
}

/// `save(new ApiKeyEntity)`.
pub(crate) async fn insert(db: &Db, row: &KeyRow) -> Result<(), StoreError> {
    let id = row.id.as_hyphenated().to_string();
    let created = to_microseconds(row.created_at);
    let used = row.last_used_at.map(to_microseconds);
    let expires = row.expires_at.map(to_microseconds);
    match db {
        Db::MySql(pool) => {
            sqlx::query(
                "/* mysql */ insert into t_api_key (id, name, key_hash, prefix, created_at, last_used_at, scopes, \
                 target_kind, target_id, expires_at, owner_user_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(&row.name)
            .bind(&row.key_hash)
            .bind(&row.prefix)
            .bind(created)
            .bind(used)
            .bind(&row.scopes)
            .bind(&row.target_kind)
            .bind(row.target_id)
            .bind(expires)
            .bind(row.owner_user_id)
            .execute(pool)
            .await?;
        }
        Db::PostgreSql(pool) => {
            sqlx::query(
                "/* postgres */ insert into t_api_key (id, name, key_hash, prefix, created_at, last_used_at, scopes, \
                 target_kind, target_id, expires_at, owner_user_id) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            )
            .bind(id)
            .bind(&row.name)
            .bind(&row.key_hash)
            .bind(&row.prefix)
            .bind(created)
            .bind(used)
            .bind(&row.scopes)
            .bind(&row.target_kind)
            .bind(row.target_id)
            .bind(expires)
            .bind(row.owner_user_id)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// `deleteById`: revoking deletes the row — a "disabled" key that something could re-enable by accident would be
/// worse than an absent one. The audit trail keeps the record.
pub(crate) async fn delete(db: &Db, id: Uuid) -> Result<u64, StoreError> {
    let id = id.as_hyphenated().to_string();
    Ok(match db {
        Db::MySql(pool) => {
            sqlx::query("/* mysql */ delete from t_api_key where id = ?").bind(id).execute(pool).await?.rows_affected()
        }
        Db::PostgreSql(pool) => sqlx::query("/* postgres */ delete from t_api_key where id = $1")
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected(),
    })
}

/// `revokeOwnedBy`: every key an account issued — when the account goes, the keys that borrow its authority go too.
pub(crate) async fn delete_owned_by(db: &Db, owner: i64) -> Result<u64, StoreError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query("/* mysql */ delete from t_api_key where owner_user_id = ?")
            .bind(owner)
            .execute(pool)
            .await?
            .rows_affected(),
        Db::PostgreSql(pool) => sqlx::query("/* postgres */ delete from t_api_key where owner_user_id = $1")
            .bind(owner)
            .execute(pool)
            .await?
            .rows_affected(),
    })
}
