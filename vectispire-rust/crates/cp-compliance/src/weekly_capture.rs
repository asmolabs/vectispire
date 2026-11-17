//! The weekly OWASP record — Java's `OwaspWeeklyCoverageService`: every target's grid, its unsettled findings and
//! its settled ones apart, written for the current week at most every six hours, the week rewritten whole.

use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use vectispire_cp_db::{Db, ScanTarget};
use vectispire_cp_targets::Clock;

use crate::coverage::OwaspCoverageService;
use crate::error::ComplianceError;
use crate::persistence::repository::WeeklyRepository;
use crate::persistence::{self, KIND_CONTAINER, KIND_REPOSITORY, WeeklyRow};
use crate::weekly::monday;

/// How often the current week is rewritten.
pub const INTERVAL: Duration = Duration::hours(6);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Captured,
    NotDue,
    TakenElsewhere,
    Failed,
}

#[derive(Clone)]
pub struct OwaspWeeklyCoverageService {
    db: Db,
    coverage: OwaspCoverageService,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for OwaspWeeklyCoverageService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OwaspWeeklyCoverageService").finish_non_exhaustive()
    }
}

impl OwaspWeeklyCoverageService {
    pub fn new(db: Db, coverage: OwaspCoverageService, clock: Arc<dyn Clock>) -> OwaspWeeklyCoverageService {
        OwaspWeeklyCoverageService { db, coverage, clock }
    }

    /// `capture()`: never fails outward. **Read outside the transaction, written inside one that checks again** — the
    /// reading is long, and two instances racing for the week must leave one week, not two halves of it.
    pub async fn capture(&self) -> Outcome {
        let now = self.clock.now();
        let week = match monday(now) {
            Ok(week) => week,
            Err(failed) => return self.after_failure(None, now, &failed).await,
        };
        match self.attempt(week, now).await {
            Ok(outcome) => outcome,
            Err(failed) => self.after_failure(Some(week), now, &failed).await,
        }
    }

    async fn attempt(&self, week: OffsetDateTime, now: OffsetDateTime) -> Result<Outcome, ComplianceError> {
        if !self.due(week, now).await? {
            return Ok(Outcome::NotDue);
        }
        let rows = self.read(week, now).await?;
        let mut tx = persistence::write(&self.db).await?;
        if !due_in(&mut tx, week, now).await? {
            return Ok(Outcome::TakenElsewhere);
        }
        WeeklyRepository::delete_week(&mut tx, week).await?;
        WeeklyRepository::insert_all(&mut tx, &rows).await?;
        persistence::commit(tx).await?;
        Ok(Outcome::Captured)
    }

    async fn read(&self, week: OffsetDateTime, now: OffsetDateTime) -> Result<Vec<WeeklyRow>, ComplianceError> {
        let reading = self.coverage.reading().await?;
        let mut rows = Vec::new();
        for target in self.coverage.existing_targets().await? {
            let (kind, id) = match target {
                ScanTarget::Repository(id) => (KIND_REPOSITORY, id),
                ScanTarget::Container(id) => (KIND_CONTAINER, id),
            };
            for line in self.coverage.of_target(target, &reading).await? {
                rows.push(WeeklyRow {
                    week_start: week,
                    target_kind: kind.to_owned(),
                    target_id: id,
                    state: state_name(line.state)?,
                    category: line.id,
                    open_count: line.open,
                    settled_count: line.settled,
                    captured_at: now,
                });
            }
        }
        Ok(rows)
    }

    async fn due(&self, week: OffsetDateTime, now: OffsetDateTime) -> Result<bool, ComplianceError> {
        let mut tx = persistence::read(&self.db).await?;
        let due = due_in(&mut tx, week, now).await?;
        persistence::commit(tx).await?;
        Ok(due)
    }

    /// Another instance's capture since the failure is not a failure: the week was written.
    async fn after_failure(
        &self,
        week: Option<OffsetDateTime>,
        now: OffsetDateTime,
        failed: &ComplianceError,
    ) -> Outcome {
        if let Some(week) = week
            && let Ok(false) = self.due(week, now).await
        {
            tracing::info!("OWASP weekly coverage for {week} written by another instance meanwhile.");
            return Outcome::TakenElsewhere;
        }
        tracing::warn!("OWASP weekly coverage capture skipped: {failed}");
        Outcome::Failed
    }
}

/// Due when the week has no row, or its newest capture is at least six hours old.
async fn due_in(
    tx: &mut vectispire_cp_db::Tx,
    week: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<bool, ComplianceError> {
    let newest = WeeklyRepository::newest_capture_of(tx, week).await?;
    Ok(match (newest, now.checked_sub(INTERVAL)) {
        (None, _) => true,
        (Some(newest), Some(gate)) => newest <= gate,
        (Some(_), None) => false,
    })
}

fn state_name(state: vectispire_domain::owasp_coverage::State) -> Result<String, ComplianceError> {
    match serde_json::to_value(state).map_err(ComplianceError::unexpected)? {
        serde_json::Value::String(name) => Ok(name),
        other => Err(ComplianceError::unexpected(format!("not a state name: {other}"))),
    }
}
