//! The tables compliance owns: `t_control_declaration`, `t_compliance_snapshot`, `t_ai_review_result` and
//! `t_owasp_weekly_coverage`.

pub(crate) mod entities;
pub mod repository;
#[cfg(test)]
mod tests;

use time::OffsetDateTime;
pub use vectispire_cp_db::query::{KIND_CONTAINER, KIND_REPOSITORY};
use vectispire_cp_db::{Db, Tx};

#[derive(Debug, thiserror::Error)]
#[error("the compliance tables did not answer: {0}")]
pub struct StoreError(#[source] pub Box<dyn std::error::Error + Send + Sync>);

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> StoreError {
        StoreError(Box::new(error))
    }
}

pub async fn read(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(vectispire_cp_db::Mode::ReadOnly).await?)
}

pub async fn write(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(vectispire_cp_db::Mode::ReadWrite).await?)
}

pub async fn commit(tx: Tx) -> Result<(), StoreError> {
    Ok(tx.commit().await?)
}

/// One line of the declaration of applicability — `ControlDeclarationEntity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationRow {
    pub id: String,
    pub framework: String,
    pub control_id: String,
    pub applicability: String,
    pub justification: Option<String>,
    pub implementation: Option<String>,
    pub evidence_source: String,
    pub external_evidence: Option<String>,
    pub control_owner: Option<String>,
    pub decided_by: Option<String>,
    pub decided_at: OffsetDateTime,
    pub reviewed_at: Option<OffsetDateTime>,
    pub review_due_at: Option<OffsetDateTime>,
}

/// One month's capture of one framework — `ComplianceSnapshotEntity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRow {
    pub id: String,
    pub period: String,
    pub framework: String,
    pub score: i32,
    pub status: String,
    pub targets: i32,
    pub observed_targets: i32,
    pub fresh_targets: i32,
    pub freshness_days: i32,
    pub eol_enabled: bool,
    pub code_analysis_reaches: bool,
    pub controls_total: i32,
    pub controls_declared: i32,
    pub soa_findings: i32,
    pub captured_at: OffsetDateTime,
}

/// One OWASP report — `AiReviewResultEntity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRow {
    pub id: i64,
    pub scan_id: i64,
    pub model: String,
    pub prompt: String,
    pub response: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub created_at: OffsetDateTime,
    pub inputs: Option<String>,
    pub deadline_at: Option<OffsetDateTime>,
    pub repo_id: Option<i64>,
    pub evidence_identifiers: Option<String>,
}

/// A report about to be asked for: every column but the key the engine generates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReview {
    pub scan_id: i64,
    pub model: String,
    pub prompt: String,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub inputs: Option<String>,
    pub deadline_at: Option<OffsetDateTime>,
    pub repo_id: Option<i64>,
    pub evidence_identifiers: Option<String>,
}

/// One target's line of one week's OWASP record — `OwaspWeeklyCoverageEntity`, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeeklyRow {
    pub week_start: OffsetDateTime,
    pub target_kind: String,
    pub target_id: i64,
    pub category: String,
    pub state: String,
    pub open_count: i64,
    pub settled_count: i64,
    pub captured_at: OffsetDateTime,
}

/// The weekly record summed over a reader's targets — `OwaspWeeklyStateCount`: per week, category and recorded state,
/// how many targets read that state and what they counted; `captured_at` the newest capture among these rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeeklyStateCount {
    pub week_start: OffsetDateTime,
    pub category: String,
    pub state: String,
    pub targets: i64,
    pub open: i64,
    pub settled: i64,
    pub captured_at: OffsetDateTime,
}

/// A target the weekly record names — `OwaspWeeklyTarget`, what the orphan sweep checks.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WeeklyTarget {
    pub kind: String,
    pub id: i64,
}
