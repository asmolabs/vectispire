//! `t_audit_log` and `t_audit_chain_head` — every query of the module, on each engine.
//!
//! **Checked statements, `sqlx::query!`, one module per engine** (`mysql.rs`, `postgres.rs`): each is described by
//! a real server of its engine while compiling, migrated by the real Flyway, and the answers are kept in this
//! crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh check cp-audit`). A column renamed, a type changed or a
//! nullability moved by a migration does not build — what Hibernate's `validate` and its parse of each `@Query`
//! did at start. Every statement starts with its engine's tag, as `cp-db`'s do: the cache file is named after a
//! hash of the text alone, and a statement spelled alike on both engines would name one file twice.
//!
//! **Each engine's module is a feature** (`mysql-queries`, `postgres-queries`, both on by default), so the cache
//! script can compile one engine's statements against that engine alone; the functions below dispatch on the
//! engine, and an engine compiled out answers [`DbError::EngineNotCompiled`] — which only that script's build
//! can reach.
//!
//! The one statement that is not checked is MySQL's `resource_id in (?, …)`, whose text follows the batch's
//! length, as Hibernate expands a collection; it is exercised on its engine by the live suite.

#[cfg(feature = "mysql-queries")]
mod mysql;
#[cfg(feature = "postgres-queries")]
mod postgres;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::{Db, LockConflict, Tx};

/// A row of `t_audit_log` — `AuditLogEntity`. It stays in this layer: the module's API hands out
/// `StoredEntry`, as Java's routes hand out `AuditEntryView` and never the entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: Uuid,
    pub description: String,
    pub operation_type: String,
    pub resource_id: String,
    pub timestamp: OffsetDateTime,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub previous_hash: Option<String>,
    pub entry_hash: Option<String>,
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

impl LockConflict for DbError {
    fn is_lock_conflict(&self) -> bool {
        matches!(self, DbError::Sql(failure) if vectispire_cp_db::is_lock_conflict(failure))
    }
}

/// Dispatches one statement to the engine's module: `on!(db_or_tx, Variant => engine::function(arguments))`. The
/// arm of an engine compiled out answers [`DbError::EngineNotCompiled`]; with both on — every build but the cache
/// script's — that arm does not exist.
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

/// `AuditChainHeadRepository.lock`: `select … for update` on V66's one row, held until the entry's transaction
/// ends — the next writer, on this instance, another, or a Java one, waits here instead of reading the same head.
/// `false` only if the row was deleted by hand, which the caller refuses rather than writing unlocked.
///
/// `for update` and not PostgreSQL's weaker `for no key update`: whatever Hibernate takes for a pessimistic write,
/// `for update` conflicts with it, so a Rust and a Java writer exclude each other either way.
pub async fn lock_chain(tx: &mut Tx) -> Result<bool, DbError> {
    on!(tx, Tx, |t| mysql::lock_chain(t).await, postgres::lock_chain(t).await)
}

/// `findTopByOrderByTimestampDescIdDesc`: the entry the next one chains onto, in the verification's order
/// reversed — by timestamp alone, two entries of one millisecond would let the chain be built onto one and
/// verified against the other.
pub async fn head(tx: &mut Tx) -> Result<Option<Row>, DbError> {
    on!(tx, Tx, |t| mysql::head(t).await, postgres::head(t).await)
}

/// The insert, issued at once — Java flushes inside its `try` for the same reason: a refusal must reach the
/// caller's error path before the mirror line is written.
pub async fn insert(tx: &mut Tx, entry: &Row) -> Result<(), DbError> {
    on!(tx, Tx, |t| mysql::insert(t, entry).await, postgres::insert(t, entry).await)
}

/// `findAllByOrderByTimestampAscIdAsc`: the whole log in chain order. Two entries of one millisecond by two
/// instances are a legitimate fork, and the id breaks the tie deterministically.
pub async fn all_in_chain_order(db: &Db) -> Result<Vec<Row>, DbError> {
    on!(db, Db, |pool| mysql::all_in_chain_order(pool).await, postgres::all_in_chain_order(pool).await)
}

/// `findRecent`: the newest entries, for the screen.
pub async fn recent(db: &Db, limit: i64) -> Result<Vec<Row>, DbError> {
    on!(db, Db, |pool| mysql::recent(pool, limit).await, postgres::recent(pool, limit).await)
}

/// `updateHashes`: rewrites one entry's hashes, for the rebuild and nothing else — a targeted update, so nothing
/// else of a row on this table is ever written.
pub async fn update_hashes(
    tx: &mut Tx,
    id: Uuid,
    previous_hash: Option<&str>,
    entry_hash: &str,
) -> Result<u64, DbError> {
    on!(
        tx,
        Tx,
        |t| mysql::update_hashes(t, id, previous_hash, entry_hash).await,
        postgres::update_hashes(t, id, previous_hash, entry_hash).await
    )
}

/// `count()`.
pub async fn count(db: &Db) -> Result<i64, DbError> {
    on!(db, Db, |pool| mysql::count(pool).await, postgres::count(pool).await)
}

/// `countByOperationTypeAndTimestampGreaterThanEqual`.
pub async fn count_since(db: &Db, operation_type: &str, since: OffsetDateTime) -> Result<i64, DbError> {
    on!(
        db,
        Db,
        |pool| mysql::count_since(pool, operation_type, since).await,
        postgres::count_since(pool, operation_type, since).await
    )
}

/// `findResourcesNamed`, for one batch: which of these resources at least one entry of the operation names.
pub async fn resources_named(db: &Db, operation_type: &str, ids: &[String]) -> Result<Vec<String>, DbError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    on!(
        db,
        Db,
        |pool| mysql::resources_named(pool, operation_type, ids).await,
        postgres::resources_named(pool, operation_type, ids).await
    )
}

/// `distinctOperationTypes`: the values actually present, so the filter offers nothing empty.
pub async fn distinct_operation_types(db: &Db) -> Result<Vec<String>, DbError> {
    on!(db, Db, |pool| mysql::distinct_operation_types(pool).await, postgres::distinct_operation_types(pool).await)
}

/// `findFiltered`'s criteria. Every filter optional, expressed as a null check rather than as several
/// statements: several statements are several orderings to keep in step, on the one table whose value is that it
/// reads the same to everybody.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub operation_type: Option<String>,
    pub user_id: Option<String>,
    /// Already lower-cased and wrapped in `%`, as the service builds it.
    pub pattern: Option<String>,
}

/// One page of the filtered log, newest first, and how many entries the filter matches.
pub async fn filtered(db: &Db, filter: &Filter, limit: i64, offset: i64) -> Result<(Vec<Row>, i64), DbError> {
    on!(
        db,
        Db,
        |pool| mysql::filtered(pool, filter, limit, offset).await,
        postgres::filtered(pool, filter, limit, offset).await
    )
}
