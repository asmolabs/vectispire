//! The tables `gate` owns: `t_gate_policy` and `t_gate_verdict`.

pub mod repository;
#[cfg(test)]
mod tests;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Tx};

#[derive(Debug, thiserror::Error)]
#[error("the gate tables did not answer: {0}")]
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

/// A stored gate policy row in `t_gate_policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatePolicyRow {
    pub id: i64,
    pub target_kind: String,
    pub target_id: i64,
    pub version: i32,
    pub is_active: Option<bool>,
    pub fail_on_severity: Option<String>,
    pub fail_on_kev: bool,
    pub fixable_only: bool,
    pub include_triaged: bool,
    pub include_ai_review: bool,
    pub fail_on_uncovered_languages: bool,
    pub include_plugins: bool,
    pub note: Option<String>,
    pub created_by: Option<String>,
    pub created_at: OffsetDateTime,
}

/// A new gate policy to be inserted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGatePolicyRow {
    pub target_kind: String,
    pub target_id: i64,
    pub version: i32,
    pub is_active: Option<bool>,
    pub fail_on_severity: Option<String>,
    pub fail_on_kev: bool,
    pub fixable_only: bool,
    pub include_triaged: bool,
    pub include_ai_review: bool,
    pub fail_on_uncovered_languages: bool,
    pub include_plugins: bool,
    pub note: Option<String>,
    pub created_by: Option<String>,
    pub created_at: OffsetDateTime,
}

/// A gate verdict row in `t_gate_verdict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateVerdictRow {
    pub id: String,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub passed: bool,
    pub evaluated: i32,
    pub violations: i32,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub fail_on_severity: Option<String>,
    pub policy_source: String,
    pub policy_version: Option<i64>,
    pub relaxations_ignored: bool,
    pub decided_at: OffsetDateTime,
    pub decided_by: Option<String>,
    pub ip_address: Option<String>,
}
