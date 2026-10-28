//! `t_one_shot_job` — the jobs that ran once on this database (V46). No upsert and no read-then-write: the row is
//! written by one insert whose primary key arbitrates, and a merge that reads first would let both callers win.
//!
//! **Checked statements, `sqlx::query!`, one module per engine**, each described by a migrated server of its engine
//! while compiling and kept in this crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh check cp-maintenance`) —
//! the arrangement and its reasons are `cp-audit`'s persistence's, and `cp-db`'s README's.

#[cfg(feature = "mysql-queries")]
mod mysql;
#[cfg(feature = "postgres-queries")]
mod postgres;

use time::OffsetDateTime;
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

/// `OneShotJobRepository.claim`: inserts the job's row in the caller's transaction, or fails because it is there.
/// The instant is stored at the microsecond, truncated, as Java's microsecond clock writes it: the drivers send no
/// finer, so no rounding here (`tests/engines.rs` holds a nanosecond instant to it on both engines).
pub async fn claim(tx: &mut Tx, name: &str, at: OffsetDateTime) -> Result<u64, DbError> {
    on!(tx, Tx, |t| mysql::claim(t, name, at).await, postgres::claim(t, name, at).await)
}

/// `existsById`, on a connection of its own: it reads what is committed.
pub async fn exists(db: &Db, name: &str) -> Result<bool, DbError> {
    on!(db, Db, |pool| mysql::exists(pool, name).await, postgres::exists(pool, name).await)
}
