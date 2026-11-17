//! The monthly history — the read half of Java's `ComplianceHistoryService`: every framework's captures, each
//! attributed to what plausibly moved it. The capture, which reads the OWASP grid's reach of code analysis, comes with
//! the grid (stage 3).

use vectispire_cp_db::Db;

use crate::decisions::{ComplianceFramework, ComplianceSnapshot, Series, Status, history};
use crate::error::ComplianceError;
use crate::matrix::instant;
use crate::persistence::repository::SnapshotRepository;
use crate::persistence::{self, SnapshotRow};

#[derive(Debug, Clone)]
pub struct ComplianceHistoryService {
    db: Db,
}

impl ComplianceHistoryService {
    pub fn new(db: Db) -> ComplianceHistoryService {
        ComplianceHistoryService { db }
    }

    /// The series of every framework in the enum's order, **a framework never captured left out**. A row naming a
    /// framework this build does not carry is dropped; one carrying an unknown status throws, as Java's `valueOf`.
    pub async fn history(&self) -> Result<Vec<Series>, ComplianceError> {
        let mut tx = persistence::read(&self.db).await?;
        let rows = SnapshotRepository::all_ordered(&mut tx).await?;
        persistence::commit(tx).await?;
        let mut all = Vec::with_capacity(rows.len());
        for row in &rows {
            if let Some(snapshot) = to_domain(row)? {
                all.push(snapshot);
            }
        }
        Ok(ComplianceFramework::ALL
            .into_iter()
            .map(|framework| history::of(framework, &all))
            .filter(|series| !series.steps.is_empty())
            .collect())
    }
}

fn to_domain(row: &SnapshotRow) -> Result<Option<ComplianceSnapshot>, ComplianceError> {
    let Some(framework) = ComplianceFramework::from_name(&row.framework) else {
        return Ok(None);
    };
    let status = [Status::Compliant, Status::Partial, Status::NonCompliant, Status::NoData]
        .into_iter()
        .find(|status| status.name() == row.status)
        .ok_or_else(|| ComplianceError::unexpected(format!("No enum constant {}", row.status)))?;
    Ok(Some(ComplianceSnapshot {
        period: row.period.clone(),
        framework,
        score: row.score,
        status,
        targets: row.targets,
        observed: row.observed_targets,
        fresh: row.fresh_targets,
        freshness_days: row.freshness_days,
        end_of_life_enabled: row.eol_enabled,
        code_analysis_reaches: row.code_analysis_reaches,
        controls_total: row.controls_total,
        controls_declared: row.controls_declared,
        soa_findings: row.soa_findings,
        captured_at: instant(row.captured_at),
    }))
}
