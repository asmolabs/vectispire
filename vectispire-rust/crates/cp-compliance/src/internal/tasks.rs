//! Compliance's hourly maintenance — Java's `SnapshotRetentionTask`, `OwaspWeeklyRetentionTask` and
//! `AbandonedReviewsTask`. Each catches and
//! logs, as every task does: a failure here leaves the next turn to try again, and stops no other task.

use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::Clock;
use vectispire_domain::instant::Instant;
use vectispire_domain::owasp_coverage::week_start;
use vectispire_domain::retention::evidence;

use crate::persistence::repository::{ReviewRepository, SnapshotRepository, WeeklyRepository};
use crate::persistence::{self, StoreError};

/// `AiReviewStatus.ABANDONED`: what a report a stopped process left running says once settled.
pub const ABANDONED: &str = "The control plane stopped before the model answered, and nothing is waiting for this \
                             report any more. Ask for it again.";

/// `AiReviewStatus` wire names.
pub const RUNNING: &str = "running";
pub const FAILED: &str = "failed";

/// `EvidenceRetention.cutoff` at the clock's instant: `None` when the dial keeps evidence indefinitely.
fn evidence_cutoff(days: i32, now: OffsetDateTime) -> Option<OffsetDateTime> {
    let cutoff = evidence::cutoff(days, Instant { epoch_second: now.unix_timestamp(), nano: now.nanosecond() })?;
    let at = OffsetDateTime::from_unix_timestamp(cutoff.epoch_second).ok()?;
    Some(at.replace_nanosecond(cutoff.nano).unwrap_or(at))
}

/// The monthly captures past the evidence window, removed — `EVIDENCE_RETENTION_DAYS`, not the payload window: this
/// is the record an assessment reads, not a blob that scanning again regenerates.
#[derive(Clone)]
pub struct SnapshotRetentionTask {
    db: Db,
    settings: Settings,
    clock: Arc<dyn Clock>,
}

impl SnapshotRetentionTask {
    pub fn new(db: Db, settings: Settings, clock: Arc<dyn Clock>) -> SnapshotRetentionTask {
        SnapshotRetentionTask { db, settings, clock }
    }

    async fn purge(&self) -> Result<u64, String> {
        let days = self.settings.as_int(Setting::EvidenceRetentionDays).await.map_err(|e| e.to_string())?;
        let Some(cutoff) = evidence_cutoff(days, self.clock.now()) else {
            return Ok(0);
        };
        let mut tx = persistence::write(&self.db).await.map_err(|e| e.to_string())?;
        let purged = SnapshotRepository::delete_before(&mut tx, cutoff).await.map_err(|e| e.to_string())?;
        persistence::commit(tx).await.map_err(|e| e.to_string())?;
        Ok(purged)
    }
}

impl MaintenanceTask for SnapshotRetentionTask {
    fn sequence(&self) -> Sequence {
        Sequence::ComplianceSnapshots
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            match self.purge().await {
                Ok(0) => {}
                Ok(purged) => {
                    tracing::info!("Maintenance: {purged} compliance snapshot(s) past the evidence window removed.");
                }
                Err(failed) => tracing::warn!("Compliance snapshot purge skipped: {failed}"),
            }
            Ok(())
        })
    }
}

impl std::fmt::Debug for SnapshotRetentionTask {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SnapshotRetentionTask").finish_non_exhaustive()
    }
}

/// `OwaspWeeklyCoverageService.purgeEndedBefore`: every week that starts before the Monday of the cutoff's week — the
/// week the cutoff falls in stays whole, since a week is captured whole and read whole.
pub async fn purge_weeks_ended_before(db: &Db, cutoff: OffsetDateTime) -> Result<u64, StoreError> {
    let monday = week_start(Instant { epoch_second: cutoff.unix_timestamp(), nano: cutoff.nanosecond() });
    let monday =
        OffsetDateTime::from_unix_timestamp(monday.epoch_second).map_err(|error| StoreError(Box::new(error)))?;
    let mut tx = persistence::write(db).await?;
    let purged = WeeklyRepository::delete_weeks_before(&mut tx, monday).await?;
    persistence::commit(tx).await?;
    Ok(purged)
}

/// The weekly OWASP record past the evidence window, removed by whole weeks.
#[derive(Clone)]
pub struct WeeklyRetentionTask {
    db: Db,
    settings: Settings,
    clock: Arc<dyn Clock>,
}

impl WeeklyRetentionTask {
    pub fn new(db: Db, settings: Settings, clock: Arc<dyn Clock>) -> WeeklyRetentionTask {
        WeeklyRetentionTask { db, settings, clock }
    }

    async fn purge(&self) -> Result<u64, String> {
        let days = self.settings.as_int(Setting::EvidenceRetentionDays).await.map_err(|e| e.to_string())?;
        let Some(cutoff) = evidence_cutoff(days, self.clock.now()) else {
            return Ok(0);
        };
        purge_weeks_ended_before(&self.db, cutoff).await.map_err(|e| e.to_string())
    }
}

impl MaintenanceTask for WeeklyRetentionTask {
    fn sequence(&self) -> Sequence {
        Sequence::OwaspWeeklyRetention
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            match self.purge().await {
                Ok(0) => {}
                Ok(purged) => tracing::info!(
                    "Maintenance: {purged} weekly OWASP coverage row(s) past the evidence window removed."
                ),
                Err(failed) => tracing::warn!("Weekly OWASP coverage purge skipped: {failed}"),
            }
            Ok(())
        })
    }
}

impl std::fmt::Debug for WeeklyRetentionTask {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("WeeklyRetentionTask").finish_non_exhaustive()
    }
}

/// `OwaspReviewService.settleAbandoned`: the reports still running past their deadline — requests whose process stopped
/// between asking the model and writing its answer — settled as failed, with [`ABANDONED`].
pub async fn settle_abandoned(db: &Db, now: OffsetDateTime) -> Result<u64, StoreError> {
    let mut tx = persistence::write(db).await?;
    let settled = ReviewRepository::settle_abandoned(&mut tx, RUNNING, FAILED, ABANDONED, now).await?;
    persistence::commit(tx).await?;
    Ok(settled)
}

/// `AbandonedReviewsTask`: [`settle_abandoned`], hourly.
#[derive(Clone)]
pub struct AbandonedReviewsTask {
    db: Db,
    clock: Arc<dyn Clock>,
}

impl AbandonedReviewsTask {
    pub fn new(db: Db, clock: Arc<dyn Clock>) -> AbandonedReviewsTask {
        AbandonedReviewsTask { db, clock }
    }
}

impl MaintenanceTask for AbandonedReviewsTask {
    fn sequence(&self) -> Sequence {
        Sequence::AbandonedReviews
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            match settle_abandoned(&self.db, self.clock.now()).await {
                Ok(0) => {}
                Ok(settled) => tracing::info!(
                    "Maintenance: {settled} model review(s) abandoned by a stopped process settled as failed."
                ),
                Err(failed) => tracing::warn!("Abandoned model reviews not settled: {failed}"),
            }
            Ok(())
        })
    }
}

impl std::fmt::Debug for AbandonedReviewsTask {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AbandonedReviewsTask").finish_non_exhaustive()
    }
}
