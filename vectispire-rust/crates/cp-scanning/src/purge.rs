//! A purged target's findings and scans — `ScanPurge`'s two listeners and `PurgedScans`.
//!
//! **Findings by scan here, by issue in `issues`' listener, both in the findings phase**: a finding hangs off a scan and,
//! once synced, off an issue; the target's issues and scans are the same target's, so each selection should find the
//! same rows — and taking both is what makes that an assumption nobody has to hold. Both run in the deleting
//! transaction, handed as `&mut Tx`: a listener cannot commit its deletes on its own while the target stays.

use std::sync::Arc;

use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::{ListenerName, Phase, PurgeListener, TargetPurge};

use crate::persistence::{self, LOOKUP_BATCH, StoreError};

/// `PurgedScans.inBatches`: every scan a purge takes — every one of a deleted target, or every one whose target is
/// gone — handed to `action` a thousand at a time; answers how many. **In batches**, because a target's scans are sized
/// by its history and the orphans' cleanup takes every deleted target's at once: one bind parameter per identifier was
/// refused by the PostgreSQL driver past 65,535.
pub async fn scans_of(tx: &mut Tx, purge: &TargetPurge) -> Result<Vec<i64>, StoreError> {
    match purge {
        TargetPurge::Deleted(ScanTarget::Repository(id)) => persistence::ids_of_repository(tx, *id).await,
        TargetPurge::Deleted(ScanTarget::Container(id)) => persistence::ids_of_container(tx, *id).await,
        TargetPurge::Orphans => persistence::orphaned_ids(tx).await,
    }
}

/// `deleteFindingsOfIssues`: the findings that are occurrences of these issues, deleted — for `issues`' purge listener
/// (Phase 3), which selects the issues; the findings are this module's to delete (decision 0029).
pub async fn delete_findings_of_issues(tx: &mut Tx, issues: &[i64]) -> Result<(), StoreError> {
    for batch in issues.chunks(LOOKUP_BATCH) {
        persistence::delete_findings_of_issues(tx, batch).await?;
    }
    Ok(())
}

/// `ScanPurge.purgeFindings`, in the findings phase.
#[derive(Debug, Clone, Copy, Default)]
pub struct PurgeFindings;

impl PurgeListener for PurgeFindings {
    fn name(&self) -> ListenerName {
        ListenerName { module: "scanning", listener: "ScanPurge.purgeFindings" }
    }

    fn phase(&self) -> Phase {
        Phase::Findings
    }

    fn purge<'a>(
        &'a self,
        tx: &'a mut Tx,
        purge: &'a TargetPurge,
    ) -> BoxFuture<'a, Result<(), vectispire_cp_targets::deletion::PurgeError>> {
        Box::pin(async move {
            let scans = scans_of(tx, purge).await?;
            for batch in scans.chunks(LOOKUP_BATCH) {
                persistence::delete_findings_of_scans(tx, batch).await?;
            }
            Ok(())
        })
    }
}

/// `ScanPurge.purgeScans`, last: the scans, once nothing that hangs off them is left.
#[derive(Debug, Clone, Copy, Default)]
pub struct PurgeScans;

impl PurgeListener for PurgeScans {
    fn name(&self) -> ListenerName {
        ListenerName { module: "scanning", listener: "ScanPurge.purgeScans" }
    }

    fn phase(&self) -> Phase {
        Phase::Scans
    }

    fn purge<'a>(
        &'a self,
        tx: &'a mut Tx,
        purge: &'a TargetPurge,
    ) -> BoxFuture<'a, Result<(), vectispire_cp_targets::deletion::PurgeError>> {
        Box::pin(async move {
            let scans = scans_of(tx, purge).await?;
            for batch in scans.chunks(LOOKUP_BATCH) {
                persistence::delete_scans(tx, batch).await?;
            }
            if !scans.is_empty() {
                match purge {
                    TargetPurge::Orphans => {
                        tracing::info!(scans = scans.len(), "Cleaned up orphaned scans from deleted targets.")
                    }
                    TargetPurge::Deleted(_) => {
                        tracing::info!(scans = scans.len(), "Purged the scans of a deleted target.")
                    }
                }
            }
            Ok(())
        })
    }
}

/// The two listeners, for `PurgeRegistry::stand_ins().with(…)`: they need nothing but the deleting transaction.
pub fn listeners() -> Vec<Arc<dyn PurgeListener>> {
    vec![Arc::new(PurgeFindings), Arc::new(PurgeScans)]
}
