//! The tables `scanning` owns — `t_scan` and `t_leader_lease`, and of `t_finding` what the scan routes read and the
//! purge deletes — and every statement on them: `ScanRepository`, `LeaderLeaseRepository` and the reads of
//! `FindingRepository` this task ports. Ingestion's writes to `t_finding` are task 2.8's, in [`findings`].
//!
//! **Checked statements, `sqlx::query!`, one module per engine**, described by a migrated server of the engine while
//! compiling and kept in this crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh check cp-scanning`). Every
//! statement carries its engine's tag, because the cache file is named after the SQL text alone.
//!
//! **A list is one parameter on both engines** — an array on PostgreSQL, a JSON array read by `json_table` on MySQL —
//! and the callers keep Java's batches anyway (a thousand identifiers, five hundred for the payload purge), so that a
//! statement's size stays what Java's was.
//!
//! **Every write of the queue is conditional**, and its row count is the answer: the claim's take names the status it
//! expects and the wait it honours, a release names its owner (and its attempt), the reclaim names the lapse, the
//! leader lease names the holder and the expiry that were read. There is no row lock anywhere — see `ScanQueue`.
//!
//! **Not the payloads, by default.** A scan row is read without its SBOM, CVE list and summary, which run to megabytes:
//! a history page of two hundred scans read them all in Java to show none. Whether an SBOM is there is a column of the
//! row ([`ScanRow::has_sbom`]); the document itself is [`sbom`], read for the one route that serves it.

pub mod catalog_queries;
pub mod findings;
#[cfg(feature = "mysql-queries")]
mod mysql;
#[cfg(feature = "postgres-queries")]
mod postgres;
#[cfg(test)]
mod tests;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode, Tx};

/// How many identifiers one lookup carries — Java's `LOOKUP_BATCH` and `PURGE_BATCH`.
pub const LOOKUP_BATCH: usize = 1_000;

/// A database failure, kept in this layer: the services see a [`StoreError`].
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    /// The engine's statements were compiled out — only the one-engine build of the cache script lacks some.
    #[cfg_attr(all(feature = "mysql-queries", feature = "postgres-queries"), allow(dead_code))]
    #[error("this build holds no statements for {0}")]
    EngineNotCompiled(&'static str),
}

/// What a service sees of a failed statement.
#[derive(Debug, thiserror::Error)]
#[error("the scans' tables did not answer: {0}")]
pub struct StoreError(#[source] pub Box<dyn std::error::Error + Send + Sync>);

impl From<DbError> for StoreError {
    fn from(error: DbError) -> StoreError {
        StoreError(Box::new(error))
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> StoreError {
        StoreError(Box::new(DbError::Sql(error)))
    }
}

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

/// A row of `t_scan`, its three payloads left out but for whether the SBOM is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRow {
    pub id: i64,
    pub branch: String,
    pub sub_path: Option<String>,
    pub status: String,
    pub duration_ms: Option<i64>,
    pub findings_count: i32,
    pub new_issues_count: i32,
    pub resolved_issues_count: i32,
    pub error: Option<String>,
    pub created_at: OffsetDateTime,
    pub version: Option<String>,
    pub project_type: Option<String>,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub required_agent_label: Option<String>,
    pub claimed_by: Option<String>,
    pub claimed_at: Option<OffsetDateTime>,
    pub lease_expires_at: Option<OffsetDateTime>,
    pub attempts: i32,
    pub not_before: Option<OffsetDateTime>,
    pub plugin_steps: Option<String>,
    pub examined_types: Option<String>,
    pub detected_languages: Option<String>,
    pub sast_languages: Option<String>,
    pub has_sbom: bool,
}

/// A scan to queue: what the trigger and the scheduler write, the counts at zero and no attempt yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewScan {
    pub status: String,
    pub created_at: OffsetDateTime,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub branch: String,
    pub sub_path: Option<String>,
    pub required_agent_label: Option<String>,
    pub not_before: Option<OffsetDateTime>,
}

/// `ClaimCandidate`: a waiting scan as the claim's selection reads it — its position in claim order, and the
/// repository an exclusion is asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimCandidate {
    pub id: i64,
    pub repo_id: Option<i64>,
    pub created_at: OffsetDateTime,
}

/// A finished scan's results, as the writing transaction stores them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultWrite {
    pub id: i64,
    pub status: String,
    pub findings_count: i32,
    pub new_issues_count: i32,
    pub resolved_issues_count: i32,
    pub duration_ms: Option<i64>,
    /// Stored only when present: a result without an SBOM leaves the column as it is.
    pub sbom: Option<String>,
    /// Stored only when the result carries a project, both columns then — a scan whose clone held no manifest says
    /// nothing about the target's ecosystem.
    pub project: Option<(Option<String>, Option<String>)>,
    pub error: Option<String>,
    pub plugin_steps: Option<String>,
    pub detected_languages: Option<String>,
    /// Written when ingestion hands its set over; left as it is otherwise.
    pub examined_types: Option<String>,
}

/// A scan that still carries a payload, by the columns retention decides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadRow {
    pub id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub created_at: OffsetDateTime,
}

/// `LatestScanRow`: a target's newest scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestRow {
    pub target_id: i64,
    pub scan_id: i64,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub error: Option<String>,
}

/// A finding of one scan, as its detail lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    pub id: i64,
    pub kind: String,
    pub severity: Option<String>,
    pub identifier: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub fix_versions: Option<String>,
    pub file_path: Option<String>,
    pub line: Option<i32>,
    pub description: Option<String>,
    pub link: Option<String>,
    pub tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
}

/// A row of `t_leader_lease`, as the election reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    pub holder: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
}

/// A list of identifiers as MySQL's one parameter reads it: a JSON array.
#[cfg_attr(not(feature = "mysql-queries"), allow(dead_code))]
fn json_ids(ids: &[i64]) -> String {
    let joined: Vec<String> = ids.iter().map(i64::to_string).collect();
    format!("[{}]", joined.join(","))
}

/// A list of strings as MySQL's one parameter reads it.
#[cfg_attr(not(feature = "mysql-queries"), allow(dead_code))]
fn json_strings(values: &[String]) -> String {
    serde_json::Value::from(values.to_vec()).to_string()
}

/// A read-only transaction on `db`.
pub async fn read(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadOnly).await?)
}

/// A read-write transaction on `db`.
pub async fn write(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadWrite).await?)
}

// ── t_scan: rows ─────────────────────────────────────────────────────────────────────────────

/// Queues a scan; answers the identifier the engine gave.
pub async fn insert_scan(tx: &mut Tx, scan: &NewScan) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::insert_scan(t, scan).await, postgres::insert_scan(t, scan).await)?)
}

pub async fn scan(tx: &mut Tx, id: i64) -> Result<Option<ScanRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::scan(t, id).await, postgres::scan(t, id).await)?)
}

/// These scans, by identifier — `findAllById` after a claim's takes.
pub async fn scans_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<Vec<ScanRow>, StoreError> {
    let mut found = Vec::new();
    for chunk in ids.chunks(LOOKUP_BATCH) {
        found.extend(on!(
            &mut *tx,
            Tx,
            |t| mysql::scans_by_ids(t, &json_ids(chunk)).await,
            postgres::scans_by_ids(t, chunk).await
        )?);
    }
    Ok(found)
}

/// The SBOM of a scan: `None` when the scan does not exist, `Some(None)` when it holds none.
pub async fn sbom(tx: &mut Tx, id: i64) -> Result<Option<Option<String>>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::sbom(t, id).await, postgres::sbom(t, id).await)?)
}

pub async fn count_by_status(tx: &mut Tx, status: &str) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::count_by_status(t, status).await, postgres::count_by_status(t, status).await)?)
}

/// `countByStatusAndRepoId`.
pub async fn count_of_repository(tx: &mut Tx, status: &str, repo: i64) -> Result<i64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::count_of_repository(t, status, repo).await,
        postgres::count_of_repository(t, status, repo).await
    )?)
}

/// `countByStatusAndContainerId`.
pub async fn count_of_container(tx: &mut Tx, status: &str, container: i64) -> Result<i64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::count_of_container(t, status, container).await,
        postgres::count_of_container(t, status, container).await
    )?)
}

/// `countByStatusInAndRepoId`, the two statuses a round reads as under way.
pub async fn count_in_flight_of_repository(tx: &mut Tx, statuses: [&str; 2], repo: i64) -> Result<i64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::count_in_flight_of_repository(t, statuses, repo).await,
        postgres::count_in_flight_of_repository(t, statuses, repo).await
    )?)
}

/// `countByStatusInAndContainerId`.
pub async fn count_in_flight_of_container(tx: &mut Tx, statuses: [&str; 2], container: i64) -> Result<i64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::count_in_flight_of_container(t, statuses, container).await,
        postgres::count_in_flight_of_container(t, statuses, container).await
    )?)
}

// ── t_scan: the claim ────────────────────────────────────────────────────────────────────────

/// The claimable selection in claim order, `(created_at, id)`: due by `as_of`, routed to `labels` — a scan requiring
/// no label goes to anyone, an agent carrying none takes only those — and, for the pages after the first, past
/// `after`. Four statements, as Java's are: `in ()` is not valid everywhere, and a position bound as `null` cannot be
/// typed by PostgreSQL.
pub async fn claimable(
    tx: &mut Tx,
    status: &str,
    labels: &[String],
    as_of: OffsetDateTime,
    after: Option<(OffsetDateTime, i64)>,
    limit: i64,
) -> Result<Vec<ClaimCandidate>, StoreError> {
    Ok(match (labels.is_empty(), after) {
        (true, None) => on!(
            tx,
            Tx,
            |t| mysql::claimable_unlabelled(t, status, as_of, limit).await,
            postgres::claimable_unlabelled(t, status, as_of, limit).await
        )?,
        (true, Some((at, id))) => on!(
            tx,
            Tx,
            |t| mysql::claimable_unlabelled_after(t, status, as_of, at, id, limit).await,
            postgres::claimable_unlabelled_after(t, status, as_of, at, id, limit).await
        )?,
        (false, None) => on!(
            tx,
            Tx,
            |t| mysql::claimable(t, status, &json_strings(labels), as_of, limit).await,
            postgres::claimable(t, status, labels, as_of, limit).await
        )?,
        (false, Some((at, id))) => on!(
            tx,
            Tx,
            |t| mysql::claimable_after(t, status, &json_strings(labels), as_of, at, id, limit).await,
            postgres::claimable_after(t, status, labels, as_of, at, id, limit).await
        )?,
    })
}

/// `countDue`: the waiting scans due by `as_of`, whatever they require.
pub async fn count_due(tx: &mut Tx, status: &str, as_of: OffsetDateTime) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::count_due(t, status, as_of).await, postgres::count_due(t, status, as_of).await)?)
}

/// `take`: one row, if it is still `from` and due by `claimed_at`. The attempt is counted and the wait cleared.
pub async fn take(
    tx: &mut Tx,
    id: i64,
    from: &str,
    to: &str,
    worker: &str,
    claimed_at: OffsetDateTime,
    lease_expires_at: OffsetDateTime,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::take(t, id, from, to, worker, claimed_at, lease_expires_at).await,
        postgres::take(t, id, from, to, worker, claimed_at, lease_expires_at).await
    )?)
}

/// `renewLease`: only while the scan is still `status` and `worker`'s.
pub async fn renew_lease(
    tx: &mut Tx,
    id: i64,
    status: &str,
    worker: &str,
    lease_expires_at: OffsetDateTime,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::renew_lease(t, id, status, worker, lease_expires_at).await,
        postgres::renew_lease(t, id, status, worker, lease_expires_at).await
    )?)
}

/// `releaseOwned`: back to `to` with its lease dropped, if `owner` still holds it running.
pub async fn release_owned(
    tx: &mut Tx,
    id: i64,
    running: &str,
    owner: &str,
    to: &str,
    error: Option<&str>,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::release_owned(t, id, running, owner, to, error).await,
        postgres::release_owned(t, id, running, owner, to, error).await
    )?)
}

/// `releaseOwnedAttempt`: the same, for one attempt only — what a failure report applies.
#[allow(clippy::too_many_arguments)] // The statement's own parameters, each a condition or a column.
pub async fn release_owned_attempt(
    tx: &mut Tx,
    id: i64,
    running: &str,
    owner: &str,
    attempt: i32,
    to: &str,
    error: Option<&str>,
    not_before: Option<OffsetDateTime>,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::release_owned_attempt(t, id, running, owner, attempt, to, error, not_before).await,
        postgres::release_owned_attempt(t, id, running, owner, attempt, to, error, not_before).await
    )?)
}

/// `releaseOwnedRefunded`: back in the queue with the claim's attempt given back, never below zero.
pub async fn release_owned_refunded(
    tx: &mut Tx,
    id: i64,
    running: &str,
    owner: &str,
    to: &str,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::release_owned_refunded(t, id, running, owner, to).await,
        postgres::release_owned_refunded(t, id, running, owner, to).await
    )?)
}

/// `releaseLapsed`: the reclaim's release, only while the lease is still lapsed at `as_of`.
pub async fn release_lapsed(
    tx: &mut Tx,
    id: i64,
    running: &str,
    as_of: OffsetDateTime,
    to: &str,
    error: Option<&str>,
    not_before: Option<OffsetDateTime>,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::release_lapsed(t, id, running, as_of, to, error, not_before).await,
        postgres::release_lapsed(t, id, running, as_of, to, error, not_before).await
    )?)
}

/// `findLapsed`: the running scans whose lease lapsed, with their attempts.
pub async fn lapsed(tx: &mut Tx, status: &str, as_of: OffsetDateTime) -> Result<Vec<(i64, i32)>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::lapsed(t, status, as_of).await, postgres::lapsed(t, status, as_of).await)?)
}

/// `countHeld`: the scans `worker` holds and is still renewing — a lapsed lease is a scan nobody runs.
pub async fn count_held(tx: &mut Tx, worker: &str, status: &str, as_of: OffsetDateTime) -> Result<i64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::count_held(t, worker, status, as_of).await,
        postgres::count_held(t, worker, status, as_of).await
    )?)
}

/// `recordSastLanguages`.
pub async fn record_sast_languages(tx: &mut Tx, id: i64, column: Option<&str>) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::record_sast_languages(t, id, column).await,
        postgres::record_sast_languages(t, id, column).await
    )?)
}

/// The final write of a scan's results: its columns, and its claim cleared.
pub async fn write_result(tx: &mut Tx, write: &ResultWrite) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::write_result(t, write).await, postgres::write_result(t, write).await)?)
}

// ── t_scan: retention ────────────────────────────────────────────────────────────────────────

/// `findPayloadBearing`: **newest first** — the retention rule ranks a target's scans in that order, and any other
/// would purge the most recent ones, the very ones payloads exist for.
pub async fn payload_bearing(tx: &mut Tx) -> Result<Vec<PayloadRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::payload_bearing(t).await, postgres::payload_bearing(t).await)?)
}

pub async fn count_payload_bearing(tx: &mut Tx) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::count_payload_bearing(t).await, postgres::count_payload_bearing(t).await)?)
}

/// `dropPayloads`: real SQL `null`s — a JSON `null` literal would satisfy `is not null`, and the purge would select the
/// same rows for ever.
pub async fn drop_payloads(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::drop_payloads(t, &json_ids(ids)).await, postgres::drop_payloads(t, ids).await)?)
}

// ── t_scan: what the other modules read ──────────────────────────────────────────────────────

/// `findLatestPerRepository`: a correlated subquery, never a join on a computed maximum, which answers two rows when
/// two scans of one target share a creation instant.
pub async fn latest_per_repository(tx: &mut Tx) -> Result<Vec<LatestRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::latest_per_repository(t).await, postgres::latest_per_repository(t).await)?)
}

pub async fn latest_per_container(tx: &mut Tx) -> Result<Vec<LatestRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::latest_per_container(t).await, postgres::latest_per_container(t).await)?)
}

/// `findNewestDetectedLanguages`: each repository's newest scan in `status`, by the highest identifier.
pub async fn newest_detected_languages(
    tx: &mut Tx,
    repositories: &[i64],
    status: &str,
) -> Result<Vec<(i64, Option<String>)>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::newest_detected_languages(t, &json_ids(repositories), status).await,
        postgres::newest_detected_languages(t, repositories, status).await
    )?)
}

/// `findHistoryPage`: newest first, optionally one target's.
pub async fn history_page(
    tx: &mut Tx,
    repo: Option<i64>,
    container: Option<i64>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ScanRow>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::history_page(t, repo, container, limit, offset).await,
        postgres::history_page(t, repo, container, limit, offset).await
    )?)
}

/// `findHistoryWithin`: the same, within these repositories and these images — a scan matching through its
/// repository or, naming none, through its image.
pub async fn history_within(
    tx: &mut Tx,
    repo: Option<i64>,
    container: Option<i64>,
    repositories: &[i64],
    containers: &[i64],
    limit: i64,
    offset: i64,
) -> Result<Vec<ScanRow>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::history_within(t, repo, container, &json_ids(repositories), &json_ids(containers), limit, offset)
            .await,
        postgres::history_within(t, repo, container, repositories, containers, limit, offset).await
    )?)
}

/// `findByScanId(id, Limit)`: the scan's findings, most severe first.
pub async fn findings_of_scan(tx: &mut Tx, scan: i64, limit: i64) -> Result<Vec<FindingRow>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::findings_of_scan(t, scan, limit).await,
        postgres::findings_of_scan(t, scan, limit).await
    )?)
}

/// `countByScanId`.
pub async fn count_findings_of_scan(tx: &mut Tx, scan: i64) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::count_findings_of_scan(t, scan).await, postgres::count_findings_of_scan(t, scan).await)?)
}

// ── the purge ────────────────────────────────────────────────────────────────────────────────

pub async fn ids_of_repository(tx: &mut Tx, repo: i64) -> Result<Vec<i64>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::ids_of_repository(t, repo).await, postgres::ids_of_repository(t, repo).await)?)
}

pub async fn ids_of_container(tx: &mut Tx, container: i64) -> Result<Vec<i64>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::ids_of_container(t, container).await, postgres::ids_of_container(t, container).await)?)
}

/// `findOrphanedIds`: the scans whose target is gone — one anti-join per target table (`sql-known.toml`).
pub async fn orphaned_ids(tx: &mut Tx) -> Result<Vec<i64>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::ScanRepository::find_orphaned_ids(t).await,
        postgres::ScanRepository::find_orphaned_ids(t).await
    )?)
}

pub async fn delete_scans(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::delete_scans(t, &json_ids(ids)).await, postgres::delete_scans(t, ids).await)?)
}

/// `deleteByScanIdIn`.
pub async fn delete_findings_of_scans(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::delete_findings_of_scans(t, &json_ids(ids)).await,
        postgres::delete_findings_of_scans(t, ids).await
    )?)
}

/// `deleteByIssueIdIn`.
pub async fn delete_findings_of_issues(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::delete_findings_of_issues(t, &json_ids(ids)).await,
        postgres::delete_findings_of_issues(t, ids).await
    )?)
}

// ── the catalogue ────────────────────────────────────────────────────────────────────────────

/// `findAttemptedRepositoryScans`: waiting scans of repositories counted at least one attempt.
pub async fn attempted_repository_scans(tx: &mut Tx, status: &str) -> Result<Vec<(i64, i64)>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::attempted_repository_scans(t, status).await,
        postgres::attempted_repository_scans(t, status).await
    )?)
}

/// `resetAttempts`: a scan claimed since it was read is left as it is.
pub async fn reset_attempts(tx: &mut Tx, ids: &[i64], status: &str) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::reset_attempts(t, &json_ids(ids), status).await,
        postgres::reset_attempts(t, ids, status).await
    )?)
}

/// `countPendingByRequiredLabelAndRepository`.
pub async fn waiting_by_label_and_repository(
    tx: &mut Tx,
    status: &str,
) -> Result<Vec<(Option<String>, i64, i64)>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::waiting_by_label_and_repository(t, status).await,
        postgres::waiting_by_label_and_repository(t, status).await
    )?)
}

/// `countRunningByClaimant`.
pub async fn count_by_claimant(tx: &mut Tx, status: &str) -> Result<Vec<(String, i64)>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::count_by_claimant(t, status).await, postgres::count_by_claimant(t, status).await)?)
}

/// `countPendingByRequiredLabel`.
pub async fn count_by_required_label(tx: &mut Tx, status: &str) -> Result<Vec<(String, i64)>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::count_by_required_label(t, status).await,
        postgres::count_by_required_label(t, status).await
    )?)
}

/// `countByStatusAndClaimedBy`: a lapsed lease counted too, unlike [`count_held`].
pub async fn count_claimed_by(tx: &mut Tx, status: &str, claimant: &str) -> Result<i64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::count_claimed_by(t, status, claimant).await,
        postgres::count_claimed_by(t, status, claimant).await
    )?)
}

/// `findByStatusInOrderByCreatedAtAsc`, for the two statuses the agents' screen lists.
pub async fn with_status_oldest_first(tx: &mut Tx, statuses: [&str; 2]) -> Result<Vec<ScanRow>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::with_status_oldest_first(t, statuses).await,
        postgres::with_status_oldest_first(t, statuses).await
    )?)
}

/// `countByStatusAndCreatedAtAfter`.
pub async fn count_since(tx: &mut Tx, status: &str, after: OffsetDateTime) -> Result<i64, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::count_since(t, status, after).await, postgres::count_since(t, status, after).await)?)
}

/// `findAvgDurationMsByStatusAndCreatedAtAfter`: `None` when no such scan recorded a duration.
pub async fn average_duration_since(
    tx: &mut Tx,
    status: &str,
    after: OffsetDateTime,
) -> Result<Option<f64>, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::average_duration_since(t, status, after).await,
        postgres::average_duration_since(t, status, after).await
    )?)
}

/// `findLabelsOf`: each existing scan's branch and version.
pub async fn labels_of(tx: &mut Tx, ids: &[i64]) -> Result<Vec<(i64, String, Option<String>)>, StoreError> {
    let mut found = Vec::new();
    for chunk in ids.chunks(LOOKUP_BATCH) {
        found.extend(on!(
            &mut *tx,
            Tx,
            |t| mysql::labels_of(t, &json_ids(chunk)).await,
            postgres::labels_of(t, chunk).await
        )?);
    }
    Ok(found)
}

// ── t_leader_lease ───────────────────────────────────────────────────────────────────────────

pub async fn lease(tx: &mut Tx, name: &str) -> Result<Option<LeaseRow>, StoreError> {
    Ok(on!(tx, Tx, |t| mysql::lease(t, name).await, postgres::lease(t, name).await)?)
}

/// Renewal by the current holder, conditioned on still being it.
pub async fn renew_leadership(
    tx: &mut Tx,
    name: &str,
    holder: &str,
    expires_at: OffsetDateTime,
    at: OffsetDateTime,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::renew_leadership(t, name, holder, expires_at, at).await,
        postgres::renew_leadership(t, name, holder, expires_at, at).await
    )?)
}

/// Taking over an expired lease, conditioned on the holder **and** the expiry just read.
#[allow(clippy::too_many_arguments)] // The statement's own parameters.
pub async fn take_over_from(
    tx: &mut Tx,
    name: &str,
    holder: &str,
    expires_at: OffsetDateTime,
    at: OffsetDateTime,
    previous_holder: &str,
    previous_expiry: OffsetDateTime,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::take_over_from(t, name, holder, expires_at, at, previous_holder, previous_expiry).await,
        postgres::take_over_from(t, name, holder, expires_at, at, previous_holder, previous_expiry).await
    )?)
}

/// Taking a lease nobody holds — what a release leaves behind, both columns null.
pub async fn take_over_released(
    tx: &mut Tx,
    name: &str,
    holder: &str,
    expires_at: OffsetDateTime,
    at: OffsetDateTime,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::take_over_released(t, name, holder, expires_at, at).await,
        postgres::take_over_released(t, name, holder, expires_at, at).await
    )?)
}

pub async fn release_leadership(tx: &mut Tx, name: &str, holder: &str, at: OffsetDateTime) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::release_leadership(t, name, holder, at).await,
        postgres::release_leadership(t, name, holder, at).await
    )?)
}

/// First acquisition, a bare insert: the primary key arbitrates between two instances started together.
pub async fn insert_lease(
    tx: &mut Tx,
    name: &str,
    holder: &str,
    at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<u64, StoreError> {
    Ok(on!(
        tx,
        Tx,
        |t| mysql::insert_lease(t, name, holder, at, expires_at).await,
        postgres::insert_lease(t, name, holder, at, expires_at).await
    )?)
}
