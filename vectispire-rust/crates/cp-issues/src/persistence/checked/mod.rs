//! The issues' fixed statements, `sqlx::query!`, checked against a migrated server of each engine while compiling
//! and kept in this crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh check cp-issues`) — the arrangement of
//! `cp-settings`' persistence, one module per engine.
//!
//! **What is here and not in the repository's entities**: statements whose text never changes and that an entity
//! would only restate — a one-row insert, the counts, and the orphan sweep, which reads two other modules' tables
//! (`cp-arch-tests`' `sql-known.toml` lists it). They run on the caller's [`Tx`], the same connection the repository
//! uses, so one unit of work can hold both.

#[cfg(feature = "mysql-queries")]
mod mysql;
#[cfg(feature = "postgres-queries")]
mod postgres;

use vectispire_cp_db::Tx;

use super::repository::{NewTriageEvent, StoreError};

/// Dispatches one statement to the engine's module; an engine compiled out — only the cache script's one-engine
/// build — answers [`StoreError::Other`].
macro_rules! on {
    ($tx:expr, |$conn:ident| $mysql:expr, $postgres:expr) => {
        match $tx {
            #[cfg(feature = "mysql-queries")]
            Tx::MySql($conn) => $mysql,
            #[cfg(not(feature = "mysql-queries"))]
            Tx::MySql(_) => Err(StoreError::Other("this build holds no statements for MySQL".to_owned())),
            #[cfg(feature = "postgres-queries")]
            Tx::PostgreSql($conn) => $postgres,
            #[cfg(not(feature = "postgres-queries"))]
            Tx::PostgreSql(_) => Err(StoreError::Other("this build holds no statements for PostgreSQL".to_owned())),
        }
    };
}

pub async fn insert_triage_event(tx: &mut Tx, event: &NewTriageEvent) -> Result<(), StoreError> {
    on!(tx, |conn| mysql::insert_triage_event(conn, event).await, postgres::insert_triage_event(conn, event).await)
}

pub async fn count_by_state_and_repository(tx: &mut Tx, state: &str, repo_id: i64) -> Result<i64, StoreError> {
    on!(
        tx,
        |conn| mysql::count_by_state_and_repository(conn, state, repo_id).await,
        postgres::count_by_state_and_repository(conn, state, repo_id).await
    )
}

pub async fn count_decisions_for_repository(
    tx: &mut Tx,
    repo_id: i64,
    not_a_decision: &str,
) -> Result<i64, StoreError> {
    on!(
        tx,
        |conn| mysql::count_decisions_for_repository(conn, repo_id, not_a_decision).await,
        postgres::count_decisions_for_repository(conn, repo_id, not_a_decision).await
    )
}

pub async fn find_orphaned_ids(tx: &mut Tx) -> Result<Vec<i64>, StoreError> {
    on!(
        tx,
        |conn| mysql::IssueRepository::find_orphaned_ids(conn).await,
        postgres::IssueRepository::find_orphaned_ids(conn).await
    )
}
