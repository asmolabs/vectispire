//! A deleted target's compliance rows — Java's `OwaspCoveragePurge` (both its listeners) and `AiReviewPurge`.

use std::sync::Arc;

use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::deletion::PurgeError;
use vectispire_cp_targets::{ListenerName, Phase, PurgeListener, TargetPurge};

use crate::persistence::repository::{ReviewRepository, WeeklyRepository};
use crate::persistence::{KIND_CONTAINER, KIND_REPOSITORY};

/// `PurgedScans.inBatches`' batch.
const BATCH: usize = 1_000;

fn failed(error: impl std::error::Error + Send + Sync + 'static) -> PurgeError {
    Box::new(error)
}

/// `OwaspCoveragePurge.purge`: a deleted target's weekly rows, every week, in the deleting transaction. The record has
/// no foreign key — its targets are named by kind and id — so nothing else takes them.
#[derive(Debug, Clone, Copy, Default)]
pub struct WeeklyCoveragePurge;

impl PurgeListener for WeeklyCoveragePurge {
    fn name(&self) -> ListenerName {
        ListenerName { module: "compliance", listener: "OwaspCoveragePurge.purge" }
    }

    fn phase(&self) -> Phase {
        Phase::References
    }

    fn purge<'a>(&'a self, tx: &'a mut Tx, purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async move {
            let (kind, id) = match purge {
                TargetPurge::Deleted(ScanTarget::Repository(id)) => (KIND_REPOSITORY, *id),
                TargetPurge::Deleted(ScanTarget::Container(id)) => (KIND_CONTAINER, *id),
                // The sweep is the other listener's.
                TargetPurge::Orphans => return Ok(()),
            };
            WeeklyRepository::delete_by_target(tx, kind, id).await.map_err(failed)?;
            Ok(())
        })
    }
}

/// `OwaspCoveragePurge.sweep`: the weekly rows of targets deleted while nothing took them — every target the record
/// names, asked of the catalogue in the purge's transaction, and the missing ones' rows deleted. A kind this build does
/// not write is nobody's to judge, and is left as it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct WeeklyCoverageSweep;

impl PurgeListener for WeeklyCoverageSweep {
    fn name(&self) -> ListenerName {
        ListenerName { module: "compliance", listener: "OwaspCoveragePurge.sweep" }
    }

    fn phase(&self) -> Phase {
        Phase::References
    }

    fn purge<'a>(&'a self, tx: &'a mut Tx, purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async move {
            if !matches!(purge, TargetPurge::Orphans) {
                return Ok(());
            }
            let named = WeeklyRepository::targets(tx).await.map_err(failed)?;
            let ids_of = |kind: &str| -> Vec<i64> {
                named.iter().filter(|target| target.kind == kind).map(|target| target.id).collect()
            };
            let existing =
                vectispire_cp_targets::deletion::existing(tx, &ids_of(KIND_REPOSITORY), &ids_of(KIND_CONTAINER))
                    .await
                    .map_err(failed)?;
            let mut deleted: u64 = 0;
            for target in &named {
                let exists = match target.kind.as_str() {
                    KIND_REPOSITORY => existing.contains(&ScanTarget::Repository(target.id)),
                    KIND_CONTAINER => existing.contains(&ScanTarget::Container(target.id)),
                    _ => true,
                };
                if !exists {
                    let rows = WeeklyRepository::delete_by_target(tx, &target.kind, target.id).await.map_err(failed)?;
                    deleted = deleted.saturating_add(rows);
                }
            }
            if deleted > 0 {
                tracing::info!("Cleaned up {deleted} weekly OWASP coverage rows of deleted targets.");
            }
            Ok(())
        })
    }
}

/// `AiReviewPurge.purge`: the reports of the purge's scans, a thousand scans at a time.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReviewPurge;

impl PurgeListener for ReviewPurge {
    fn name(&self) -> ListenerName {
        ListenerName { module: "compliance", listener: "AiReviewPurge.purge" }
    }

    fn phase(&self) -> Phase {
        Phase::ScanChildren
    }

    fn purge<'a>(&'a self, tx: &'a mut Tx, purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async move {
            let scans = vectispire_cp_scanning::purge::scans_of(tx, purge).await.map_err(failed)?;
            for batch in scans.chunks(BATCH) {
                ReviewRepository::delete_by_scan_ids(tx, batch).await.map_err(failed)?;
            }
            Ok(())
        })
    }
}

/// The module's three listeners, in place of their stand-ins.
pub fn listeners() -> Vec<Arc<dyn PurgeListener>> {
    vec![Arc::new(WeeklyCoveragePurge), Arc::new(WeeklyCoverageSweep), Arc::new(ReviewPurge)]
}
