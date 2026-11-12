//! `t_setting` — a key and its value. The table knows nothing about which keys exist, which is what lets a
//! setting leave the catalog without a migration.
//!
//! **Checked statements, `sqlx::query!`, one module per engine**, each described by a migrated server of its engine
//! while compiling and kept in this crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh check cp-settings`) —
//! the arrangement and its reasons are `cp-audit`'s persistence's, and `cp-db`'s README's. The key column is a
//! reserved word on MySQL and quoted there; PostgreSQL takes it as written, as Hibernate's `"key"` does.

#[cfg(feature = "mysql-queries")]
mod mysql;
#[cfg(feature = "postgres-queries")]
mod postgres;

use vectispire_cp_db::{Db, Tx};

/// A database failure, kept in this layer: a service names this type and never the driver's.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    /// The engine's statements were compiled out — only the one-engine build of the cache script lacks some.
    #[error("this build holds no statements for {0}")]
    EngineNotCompiled(&'static str),
}

/// Dispatches one statement to the engine's module; an engine compiled out answers
/// [`DbError::EngineNotCompiled`], and with both on — every build but the cache script's — that arm does not exist.
macro_rules! on {
    ($target:expr, $enum:ident, |$handle:ident| $mysql:expr, $postgres:expr) => {
        match $target {
            #[cfg(feature = "mysql-queries")]
            $enum::MySql($handle) => $mysql,
            #[cfg(not(feature = "mysql-queries"))]
            $enum::MySql(_) => Err(DbError::EngineNotCompiled("MySQL")),
            #[cfg(feature = "postgres-queries")]
            $enum::PostgreSql($handle) => $postgres,
            #[cfg(not(feature = "postgres-queries"))]
            $enum::PostgreSql(_) => Err(DbError::EngineNotCompiled("PostgreSQL")),
        }
    };
}

/// Every row, the value absent as `None`.
pub async fn all(db: &Db) -> Result<Vec<(String, Option<String>)>, DbError> {
    on!(db, Db, |pool| mysql::all(pool).await, postgres::all(pool).await)
}

/// `findById`: `None` for no row, `Some(None)` for a row without a value.
pub async fn find(db: &Db, key: &str) -> Result<Option<Option<String>>, DbError> {
    on!(db, Db, |pool| mysql::find(pool, key).await, postgres::find(pool, key).await)
}

/// `findById`, in the caller's transaction — for a decision that the write after it depends on.
pub async fn find_in(tx: &mut Tx, key: &str) -> Result<Option<Option<String>>, DbError> {
    on!(tx, Tx, |t| mysql::find(&mut **t, key).await, postgres::find(&mut **t, key).await)
}

/// `insert`: creates a row and **fails** when the key has one — the primary key arbitrates, and the loser hears
/// about it. On its own connection, outside any caller's transaction.
pub async fn insert(db: &Db, key: &str, value: Option<&str>) -> Result<u64, DbError> {
    on!(db, Db, |pool| mysql::insert(pool, key, value).await, postgres::insert(pool, key, value).await)
}

/// `insert`, in the caller's transaction.
pub async fn insert_in(tx: &mut Tx, key: &str, value: Option<&str>) -> Result<u64, DbError> {
    on!(tx, Tx, |t| mysql::insert(&mut **t, key, value).await, postgres::insert(&mut **t, key, value).await)
}

/// `updateValue`: writes onto an existing row, and says whether there was one.
///
/// **Rows found, not rows changed, on MySQL too** — the server counts only what a write changed unless the client
/// asks for found rows, and writing the value a row already holds would then read as "no row", sending the caller
/// to an insert that collides with it. sqlx asks (`CLIENT_FOUND_ROWS`), as Connector/J does for Hibernate; the
/// suite writes a value twice to keep that true.
pub async fn update_value(tx: &mut Tx, key: &str, value: Option<&str>) -> Result<u64, DbError> {
    on!(tx, Tx, |t| mysql::update_value(t, key, value).await, postgres::update_value(t, key, value).await)
}

/// `replaceValue`: writes onto a row only if it still holds the value its writer read, and says whether it did —
/// the arbiter between instances. The second of two waits on the first's row lock, then finds the value moved,
/// on both engines (an update reads the committed row, whatever the isolation level), and is told zero.
pub async fn replace_value(tx: &mut Tx, key: &str, expected: &str, value: &str) -> Result<u64, DbError> {
    on!(
        tx,
        Tx,
        |t| mysql::replace_value(t, key, expected, value).await,
        postgres::replace_value(t, key, expected, value).await
    )
}

/// `deleteById`.
pub async fn delete(tx: &mut Tx, key: &str) -> Result<u64, DbError> {
    on!(tx, Tx, |t| mysql::delete(t, key).await, postgres::delete(t, key).await)
}
