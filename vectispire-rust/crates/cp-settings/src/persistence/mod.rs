//! `t_setting` — a key and its value. The table knows nothing about which keys exist, which is what lets a
//! setting leave the catalog without a migration.
//!
//! Run-time statements of fixed text, each exercised on both engines by `tests/engines.rs` (`cp-audit`'s
//! persistence says why not `query!`). The key column is a reserved word on MySQL and quoted there; PostgreSQL
//! takes it as written, as Hibernate's `"key"` does.

use sqlx::Row as _;
use vectispire_cp_db::{Db, Tx};

/// A database failure, kept in this layer: a service names this type and never the driver's.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct DbError(#[from] sqlx::Error);

/// Every row, the value absent as `None`.
pub async fn all(db: &Db) -> Result<Vec<(String, Option<String>)>, DbError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query("select `key`, value from t_setting")
            .fetch_all(pool)
            .await?
            .iter()
            .map(|row| Ok((row.try_get(0)?, row.try_get(1)?)))
            .collect::<Result<_, sqlx::Error>>()?,
        Db::PostgreSql(pool) => sqlx::query("select key, value from t_setting")
            .fetch_all(pool)
            .await?
            .iter()
            .map(|row| Ok((row.try_get(0)?, row.try_get(1)?)))
            .collect::<Result<_, sqlx::Error>>()?,
    })
}

/// `findById`: `None` for no row, `Some(None)` for a row without a value.
pub async fn find(db: &Db, key: &str) -> Result<Option<Option<String>>, DbError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query("select value from t_setting where `key` = ?")
            .bind(key)
            .fetch_optional(pool)
            .await?
            .map(|row| row.try_get(0))
            .transpose()?,
        Db::PostgreSql(pool) => sqlx::query("select value from t_setting where key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?
            .map(|row| row.try_get(0))
            .transpose()?,
    })
}

/// `insert`: creates a row and **fails** when the key has one — the primary key arbitrates, and the loser hears
/// about it. On its own connection, outside any caller's transaction.
pub async fn insert(db: &Db, key: &str, value: Option<&str>) -> Result<u64, DbError> {
    Ok(match db {
        Db::MySql(pool) => sqlx::query("insert into t_setting (`key`, value) values (?, ?)")
            .bind(key)
            .bind(value)
            .execute(pool)
            .await?
            .rows_affected(),
        Db::PostgreSql(pool) => sqlx::query("insert into t_setting (key, value) values ($1, $2)")
            .bind(key)
            .bind(value)
            .execute(pool)
            .await?
            .rows_affected(),
    })
}

/// `insert`, in the caller's transaction.
pub async fn insert_in(tx: &mut Tx, key: &str, value: Option<&str>) -> Result<u64, DbError> {
    Ok(match tx {
        Tx::MySql(t) => sqlx::query("insert into t_setting (`key`, value) values (?, ?)")
            .bind(key)
            .bind(value)
            .execute(&mut **t)
            .await?
            .rows_affected(),
        Tx::PostgreSql(t) => sqlx::query("insert into t_setting (key, value) values ($1, $2)")
            .bind(key)
            .bind(value)
            .execute(&mut **t)
            .await?
            .rows_affected(),
    })
}

/// `updateValue`: writes onto an existing row, and says whether there was one.
///
/// **Rows found, not rows changed, on MySQL too** — the server counts only what a write changed unless the client
/// asks for found rows, and writing the value a row already holds would then read as "no row", sending the caller
/// to an insert that collides with it. sqlx asks (`CLIENT_FOUND_ROWS`), as Connector/J does for Hibernate; the
/// suite writes a value twice to keep that true.
pub async fn update_value(tx: &mut Tx, key: &str, value: Option<&str>) -> Result<u64, DbError> {
    Ok(match tx {
        Tx::MySql(t) => sqlx::query("update t_setting set value = ? where `key` = ?")
            .bind(value)
            .bind(key)
            .execute(&mut **t)
            .await?
            .rows_affected(),
        Tx::PostgreSql(t) => sqlx::query("update t_setting set value = $1 where key = $2")
            .bind(value)
            .bind(key)
            .execute(&mut **t)
            .await?
            .rows_affected(),
    })
}

/// `replaceValue`: writes onto a row only if it still holds the value its writer read, and says whether it did —
/// the arbiter between instances. The second of two waits on the first's row lock, then finds the value moved,
/// on both engines (an update reads the committed row, whatever the isolation level), and is told zero.
pub async fn replace_value(tx: &mut Tx, key: &str, expected: &str, value: &str) -> Result<u64, DbError> {
    Ok(match tx {
        Tx::MySql(t) => sqlx::query("update t_setting set value = ? where `key` = ? and value = ?")
            .bind(value)
            .bind(key)
            .bind(expected)
            .execute(&mut **t)
            .await?
            .rows_affected(),
        Tx::PostgreSql(t) => sqlx::query("update t_setting set value = $1 where key = $2 and value = $3")
            .bind(value)
            .bind(key)
            .bind(expected)
            .execute(&mut **t)
            .await?
            .rows_affected(),
    })
}

/// `deleteById`.
pub async fn delete(tx: &mut Tx, key: &str) -> Result<u64, DbError> {
    Ok(match tx {
        Tx::MySql(t) => {
            sqlx::query("delete from t_setting where `key` = ?").bind(key).execute(&mut **t).await?.rows_affected()
        }
        Tx::PostgreSql(t) => {
            sqlx::query("delete from t_setting where key = $1").bind(key).execute(&mut **t).await?.rows_affected()
        }
    })
}
