//! `t_siem_config` — the export's one row (`SiemConfigEntity`, `SiemConfigRepository`).
//!
//! **Checked statements, `sqlx::query!`, one module per engine**, each described by a migrated server of its engine
//! while compiling and kept in this crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh check cp-siem`) — the
//! arrangement and its reasons are `cp-audit`'s persistence's and `cp-db`'s README's. Every statement is fixed: the
//! repository reads and writes one row by its key, so there is nothing for a statement builder to build.
//!
//! The table is Flyway's (V10, V32, V63) and was written before the type placeholders: `created_at` and `updated_at`
//! are `timestamp` to the second on MySQL and `timestamp without time zone` on PostgreSQL, read and written through
//! `UtcInstant` (`cp-db`'s `types`). An instant is handed in at the microsecond, as `CoreConfiguration.clock()` ticks;
//! MySQL rounds it to the second at the write, as it does Hibernate's.

#[cfg(feature = "mysql-queries")]
mod mysql;
#[cfg(feature = "postgres-queries")]
mod postgres;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Tx};

/// The configuration is one row, written with this id (`SiemConfigEntity.SINGLETON_ID`).
pub const SINGLETON_ID: i64 = 1;

/// The row, column by column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRow {
    pub id: i64,
    pub enabled: bool,
    /// What `SiemProtocol.name()` wrote — or anything a hand-edited row holds, which the readers refuse.
    pub protocol: String,
    pub endpoint: Option<String>,
    /// The authorization header's ciphertext (`v2:…`), or a clear value written before V32.
    pub auth_header: Option<String>,
    pub tls_ca_pem: Option<String>,
    pub min_severity: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// A database failure, kept in this layer: a service names this type and never the driver's.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    /// The engine's statements were compiled out — only the one-engine build of the cache script lacks some.
    #[error("this build holds no statements for {0}")]
    EngineNotCompiled(&'static str),
}

/// Dispatches one statement to the engine's module; an engine compiled out answers [`DbError::EngineNotCompiled`].
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

/// `findById(SINGLETON_ID)`, on its own connection.
pub async fn find(db: &Db) -> Result<Option<ConfigRow>, DbError> {
    on!(db, Db, |pool| mysql::find(pool).await, postgres::find(pool).await)
}

/// `findById(SINGLETON_ID)`, in the caller's transaction — the audit entry's, for the event it signals.
pub async fn find_in(tx: &mut Tx) -> Result<Option<ConfigRow>, DbError> {
    on!(tx, Tx, |t| mysql::find(&mut **t).await, postgres::find(&mut **t).await)
}

/// The first save: the row does not exist yet.
pub async fn insert(tx: &mut Tx, row: &ConfigRow) -> Result<u64, DbError> {
    on!(tx, Tx, |t| mysql::insert(t, row).await, postgres::insert(t, row).await)
}

/// Every later save. `created_at` is not written: the column is `updatable = false` in the entity.
pub async fn update(tx: &mut Tx, row: &ConfigRow) -> Result<u64, DbError> {
    on!(tx, Tx, |t| mysql::update(t, row).await, postgres::update(t, row).await)
}
