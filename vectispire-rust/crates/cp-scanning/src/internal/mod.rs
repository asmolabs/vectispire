//! The module's implementation behind its API: the queue, the leader lease, the two maintenance tasks, and the port
//! `targets` declares that this module answers (`TargetScans`). `ingestion` is task 2.8's.

mod ingestion;
pub mod leader;
pub mod queue;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};
use vectispire_cp_targets::ports::{LatestScan, PortError, QueueError, Queued, TargetScans};
use vectispire_cp_targets::views::{ContainerView, RepositoryView};

use crate::Scanning;
use crate::catalog::ScanCatalog;
use crate::persistence::LatestRow;
use crate::trigger::TriggerError;

/// `SchedulingTickTask`: the scheduler's tick, on every instance's scheduling turn — safe, since only the lease's
/// holder schedules, which the service enforces itself.
#[derive(Debug)]
pub struct SchedulingTickTask(pub Arc<Scanning>);

impl MaintenanceTask for SchedulingTickTask {
    fn sequence(&self) -> Sequence {
        Sequence::SchedulingTick
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            self.0.schedule_once().await;
            Ok(())
        })
    }
}

/// `ScanRetentionTask`: the scans' payloads lightened past their retention, hourly.
#[derive(Debug)]
pub struct ScanRetentionTask(pub Arc<Scanning>);

impl MaintenanceTask for ScanRetentionTask {
    fn sequence(&self) -> Sequence {
        Sequence::ScanRetention
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            let pruned = self.0.prune().await?;
            if pruned > 0 {
                tracing::info!(pruned, "Maintenance: scan(s) lightened.");
            }
            Ok(())
        })
    }
}

/// `TargetScanFigures`: `targets`' `TargetScans` — the same grouped queries its listings ran, and the same trigger.
/// Over the catalogue alone, so `targets` is composed with it before the rest of this module exists.
#[derive(Debug, Clone)]
pub struct TargetScanFigures(pub ScanCatalog);

fn by_target(rows: Vec<LatestRow>) -> BTreeMap<i64, LatestScan> {
    rows.into_iter()
        .map(|row| {
            (
                row.target_id,
                LatestScan { id: row.scan_id, status: row.status, created_at: row.created_at, error: row.error },
            )
        })
        .collect()
}

fn queued(result: Result<i64, TriggerError>) -> Result<Queued, QueueError> {
    match result {
        Ok(id) => Ok(Queued { id, status: "pending".to_owned() }),
        Err(TriggerError::AlreadyQueued(message)) => Err(QueueError::AlreadyQueued(message.to_owned())),
        Err(TriggerError::Store(failure)) => Err(QueueError::Failed(Box::new(failure))),
    }
}

impl TargetScans for TargetScanFigures {
    fn latest_per_repository(&self) -> BoxFuture<'_, Result<BTreeMap<i64, LatestScan>, PortError>> {
        Box::pin(async move {
            Ok(by_target(self.0.latest_per_repository().await.map_err(|failure| Box::new(failure) as PortError)?))
        })
    }

    fn latest_per_container(&self) -> BoxFuture<'_, Result<BTreeMap<i64, LatestScan>, PortError>> {
        Box::pin(async move {
            Ok(by_target(self.0.latest_per_container().await.map_err(|failure| Box::new(failure) as PortError)?))
        })
    }

    fn detected_languages<'a>(
        &'a self,
        repositories: &'a [i64],
    ) -> BoxFuture<'a, Result<BTreeMap<i64, BTreeSet<String>>, PortError>> {
        Box::pin(async move {
            let detected = self
                .0
                .newest_detected_languages(repositories)
                .await
                .map_err(|failure| Box::new(failure) as PortError)?;
            Ok(detected
                .into_iter()
                .map(|(repository, languages)| {
                    (repository, languages.into_iter().map(str::to_owned).collect::<BTreeSet<String>>())
                })
                .collect())
        })
    }

    fn queue_repository<'a>(
        &'a self,
        repository: &'a RepositoryView,
        not_before: Option<OffsetDateTime>,
    ) -> BoxFuture<'a, Result<Queued, QueueError>> {
        Box::pin(async move { queued(self.0.trigger_repository(repository, not_before).await) })
    }

    fn queue_container<'a>(&'a self, container: &'a ContainerView) -> BoxFuture<'a, Result<Queued, QueueError>> {
        Box::pin(async move { queued(self.0.trigger_container(container).await) })
    }
}
