//! The monthly history — Java's `ComplianceHistoryService`: one capture per framework and month, rewritten through
//! the month, and every framework's captures read back, each attributed to what plausibly moved it.

use std::sync::Arc;

use vectispire_cp_db::{Db, Visibility};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::Clock;

use crate::coverage::OwaspCoverageService;
use crate::decisions::{ComplianceFramework, ComplianceSnapshot, Series, Status, history, reconcile};
use crate::declarations::StatementOfApplicabilityService;
use crate::error::ComplianceError;
use crate::matrix::{ComplianceService, instant};
use crate::persistence::repository::SnapshotRepository;
use crate::persistence::{self, SnapshotRow};

#[derive(Clone)]
pub struct ComplianceHistoryService {
    db: Db,
    capture: Option<Capture>,
}

/// What a capture reads, beside the table.
#[derive(Clone)]
struct Capture {
    compliance: ComplianceService,
    soa: StatementOfApplicabilityService,
    coverage: OwaspCoverageService,
    settings: Settings,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ComplianceHistoryService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ComplianceHistoryService").finish_non_exhaustive()
    }
}

impl ComplianceHistoryService {
    /// The history read alone: nothing captured through it.
    pub fn new(db: Db) -> ComplianceHistoryService {
        ComplianceHistoryService { db, capture: None }
    }

    /// The history, and the capture the hourly task runs.
    pub fn capturing(
        db: Db,
        compliance: ComplianceService,
        soa: StatementOfApplicabilityService,
        coverage: OwaspCoverageService,
        settings: Settings,
        clock: Arc<dyn Clock>,
    ) -> ComplianceHistoryService {
        ComplianceHistoryService { db, capture: Some(Capture { compliance, soa, coverage, settings, clock }) }
    }

    /// `capture()`: the frameworks captured this month, `0` when it could not run — logged, never thrown, so the
    /// next turn tries again.
    pub async fn capture(&self) -> usize {
        match self.try_capture().await {
            Ok(captured) => captured,
            Err(failed) => {
                tracing::warn!("Compliance capture skipped: {failed}");
                0
            }
        }
    }

    async fn try_capture(&self) -> Result<usize, ComplianceError> {
        let Some(capture) = &self.capture else {
            return Err(ComplianceError::unexpected("this history was composed to be read, not captured"));
        };
        let now = capture.clock.now();
        let period = format!("{:04}-{:02}", now.year(), u8::from(now.month()));
        let everything = Visibility::everything();
        let summary = capture.compliance.summary(&everything).await?;
        let freshness_days = capture
            .settings
            .as_int(Setting::ComplianceFreshnessDays)
            .await
            .map_err(ComplianceError::unexpected)?
            .max(0);
        // Read as the OWASP grid reads it, per repository and per language: one flag recorded a Java estate as
        // reached by a Python rule set.
        let code_analysis_reaches = capture.coverage.reading().await?.code_analysis_reaches_its_repositories();
        let eol = capture.settings.is_enabled(Setting::EolEnabled).await.map_err(ComplianceError::unexpected)?;

        let mut rows = Vec::new();
        let mut unmeasured = Vec::new();
        for evaluation in &summary.evaluations {
            let framework = evaluation.framework.name();
            if !evaluation.overall_status.measured() {
                // A month with nothing measured has no verdict to chart: its zero read as a fall, then as a rise.
                unmeasured.push(framework);
                continue;
            }
            let declared = capture.soa.declarations(framework).await?;
            let statement = reconcile(evaluation, &declared, instant(now));
            rows.push(SnapshotRow {
                id: uuid::Uuid::new_v4().to_string(),
                period: period.clone(),
                framework: framework.to_owned(),
                score: evaluation.score_percentage,
                status: evaluation.overall_status.name().to_owned(),
                targets: summary.total_monitored_targets,
                // Both from the summary, not recounted: they are what capped the verdicts.
                observed_targets: summary.observed_targets,
                fresh_targets: summary.fresh_targets,
                freshness_days,
                eol_enabled: eol,
                code_analysis_reaches,
                controls_total: statement.total,
                controls_declared: statement.declared,
                soa_findings: statement.findings,
                captured_at: now,
            });
        }

        let mut tx = persistence::write(&self.db).await?;
        for framework in unmeasured {
            if let Some(existing) = SnapshotRepository::find(&mut tx, &period, framework).await? {
                SnapshotRepository::delete(&mut tx, &existing.id).await?;
            }
        }
        let captured = rows.len();
        for mut row in rows {
            match SnapshotRepository::find(&mut tx, &row.period, &row.framework).await? {
                Some(existing) => {
                    row.id = existing.id;
                    SnapshotRepository::update(&mut tx, &row).await?;
                }
                None => SnapshotRepository::insert(&mut tx, &row).await?,
            }
        }
        persistence::commit(tx).await?;
        Ok(captured)
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
