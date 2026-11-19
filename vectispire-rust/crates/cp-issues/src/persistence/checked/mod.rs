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

pub async fn reopening_migration_installed_on(tx: &mut Tx) -> Result<Vec<time::OffsetDateTime>, StoreError> {
    on!(
        tx,
        |conn| mysql::reopening_migration_installed_on(conn).await,
        postgres::reopening_migration_installed_on(conn).await
    )
}

// ------------------------------------------------------------------ tickets
// Java's `IssueRepository` ticket updates, each a fixed text: the claim columns (V95) are in no entity, and a
// conditional update whose row count names the winner is what these are for.

/// `attachTicket`: the reference a sweep opened, only on an issue that carries none — and the claim cleared.
pub async fn attach_ticket(tx: &mut Tx, id: i64, reference: &str, url: Option<&str>) -> Result<u64, StoreError> {
    on!(
        tx,
        |conn| mysql::attach_ticket(conn, id, reference, url).await,
        postgres::attach_ticket(conn, id, reference, url).await
    )
}

/// `claimTicket`: 1 when the issue is now `holder`'s — no reference, and no claim still running at `at`, its own
/// included.
pub async fn claim_ticket(
    tx: &mut Tx,
    id: i64,
    holder: &str,
    until: time::OffsetDateTime,
    at: time::OffsetDateTime,
) -> Result<u64, StoreError> {
    on!(
        tx,
        |conn| mysql::claim_ticket(conn, id, holder, until, at).await,
        postgres::claim_ticket(conn, id, holder, until, at).await
    )
}

/// `releaseTicketClaim`: only `holder`'s own claim.
pub async fn release_ticket_claim(tx: &mut Tx, id: i64, holder: &str) -> Result<u64, StoreError> {
    on!(
        tx,
        |conn| mysql::release_ticket_claim(conn, id, holder).await,
        postgres::release_ticket_claim(conn, id, holder).await
    )
}

/// `markTicketClosed`: `CLOSED:` before the reference while the issue still carries it. Java's `concat('CLOSED:',
/// :reference)` is spelt here before binding: PostgreSQL cannot type a parameter handed to `concat`, and the text
/// written is the same.
pub async fn mark_ticket_closed(tx: &mut Tx, id: i64, reference: &str) -> Result<u64, StoreError> {
    let closed = format!("CLOSED:{reference}");
    on!(
        tx,
        |conn| mysql::mark_ticket_closed(conn, id, &closed, reference).await,
        postgres::mark_ticket_closed(conn, id, &closed, reference).await
    )
}

/// `attachTicketBy`: a reference a person attached, and who — unconditional on the id, as Java's is.
pub async fn attach_ticket_by(
    tx: &mut Tx,
    id: i64,
    reference: &str,
    url: Option<&str>,
    by: &str,
) -> Result<u64, StoreError> {
    on!(
        tx,
        |conn| mysql::attach_ticket_by(conn, id, reference, url, by).await,
        postgres::attach_ticket_by(conn, id, reference, url, by).await
    )
}

/// What a checklist's figures count issues by: a built-in finding type, or one tool's fingerprint key (`plugin:<id>`,
/// `import:<source>/<tool>`) — never a type for a tool, which would count every plugin's issues as one's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsettledScope<'a> {
    Type(&'a str),
    Tool(&'a str),
}

/// `countUnsettledOfTypeWithin` / `countUnsettledOfToolWithin`: these repositories' issues in the scope, counted per
/// `(repository, severity, state)`, the settled triage left out **by `not in`** — so that a triage status this version
/// does not know is counted, never silently settled (decision 0032 §6). The three settled names are bound one
/// placeholder each: the list is fixed, and a statement whose length followed it could not be checked.
pub async fn count_unsettled_within(
    tx: &mut Tx,
    scope: UnsettledScope<'_>,
    repositories: &[i64],
    settled: [&str; 3],
) -> Result<Vec<(i64, Option<String>, String, i64)>, StoreError> {
    on!(
        tx,
        |conn| mysql::count_unsettled_within(conn, scope, &json_ids(repositories), settled).await,
        postgres::count_unsettled_within(conn, scope, repositories, settled).await
    )
}

/// A list of identifiers as MySQL's one parameter reads it — a JSON array under `json_table`, as `cp-scanning` and
/// `cp-targets` bind theirs: MySQL has no array parameter, and integers compare under no collation.
#[cfg_attr(not(feature = "mysql-queries"), allow(dead_code))]
fn json_ids(ids: &[i64]) -> String {
    let joined: Vec<String> = ids.iter().map(i64::to_string).collect();
    format!("[{}]", joined.join(","))
}
