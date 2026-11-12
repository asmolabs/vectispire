//! Purge listeners for issues: `PurgeTriageHistory`, `PurgeFindings`, and `PurgeIssues`.

use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::{ListenerName, Phase, PurgeListener, TargetPurge};

use crate::persistence::{IssueRepository, StoreError};

pub const PURGE_BATCH: usize = 1_000;

pub async fn issues_of(tx: &mut Tx, purge: &TargetPurge) -> Result<Vec<i64>, StoreError> {
    match purge {
        TargetPurge::Deleted(ScanTarget::Repository(id)) => IssueRepository::find_ids_by_repo_id(tx, *id).await,
        TargetPurge::Deleted(ScanTarget::Container(id)) => IssueRepository::find_ids_by_container_id(tx, *id).await,
        TargetPurge::Orphans => IssueRepository::find_orphaned_ids(tx).await,
    }
}

/// `IssuePurge.purgeTriageHistory`, in the `IssueChildren` phase.
#[derive(Debug, Clone, Copy, Default)]
pub struct PurgeTriageHistory;

impl PurgeListener for PurgeTriageHistory {
    fn name(&self) -> ListenerName {
        ListenerName { module: "issues", listener: "IssuePurge.purgeTriageHistory" }
    }

    fn phase(&self) -> Phase {
        Phase::IssueChildren
    }

    fn purge<'a>(
        &'a self,
        tx: &'a mut Tx,
        purge: &'a TargetPurge,
    ) -> BoxFuture<'a, Result<(), vectispire_cp_targets::deletion::PurgeError>> {
        Box::pin(async move {
            let ids = issues_of(tx, purge).await?;
            for chunk in ids.chunks(PURGE_BATCH) {
                IssueRepository::delete_triage_events_by_issue_ids(tx, chunk).await?;
            }
            Ok(())
        })
    }
}

/// `IssuePurge.purgeFindings`, in the `Findings` phase.
#[derive(Debug, Clone, Copy, Default)]
pub struct PurgeFindings;

impl PurgeListener for PurgeFindings {
    fn name(&self) -> ListenerName {
        ListenerName { module: "issues", listener: "IssuePurge.purgeFindings" }
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
            let ids = issues_of(tx, purge).await?;
            for chunk in ids.chunks(PURGE_BATCH) {
                vectispire_cp_scanning::purge::delete_findings_of_issues(tx, chunk).await?;
            }
            Ok(())
        })
    }
}

/// `IssuePurge.purgeIssues`, in the `Issues` phase.
#[derive(Debug, Clone, Copy, Default)]
pub struct PurgeIssues;

impl PurgeListener for PurgeIssues {
    fn name(&self) -> ListenerName {
        ListenerName { module: "issues", listener: "IssuePurge.purgeIssues" }
    }

    fn phase(&self) -> Phase {
        Phase::Issues
    }

    fn purge<'a>(
        &'a self,
        tx: &'a mut Tx,
        purge: &'a TargetPurge,
    ) -> BoxFuture<'a, Result<(), vectispire_cp_targets::deletion::PurgeError>> {
        Box::pin(async move {
            let ids = issues_of(tx, purge).await?;
            for chunk in ids.chunks(PURGE_BATCH) {
                IssueRepository::delete_by_ids(tx, chunk).await?;
            }
            if !ids.is_empty() {
                match purge {
                    TargetPurge::Orphans => {
                        tracing::info!(deleted = ids.len(), "Cleaned up orphaned issues from deleted targets.");
                    }
                    TargetPurge::Deleted(_) => {
                        tracing::info!(deleted = ids.len(), "Purged issues of a deleted target.");
                    }
                }
            }
            Ok(())
        })
    }
}

/// Returns the 3 purge listeners for `issues`.
pub fn listeners() -> Vec<std::sync::Arc<dyn PurgeListener>> {
    vec![std::sync::Arc::new(PurgeTriageHistory), std::sync::Arc::new(PurgeFindings), std::sync::Arc::new(PurgeIssues)]
}
