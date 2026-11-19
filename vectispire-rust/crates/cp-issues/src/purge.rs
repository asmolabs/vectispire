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

/// `PurgedIssues`: the issues a purge takes — every one of a deleted target, or every one whose target is gone — handed
/// out [`PURGE_BATCH`] identifiers at a time. **One answer for every module** purging what hangs off an issue (ticket
/// links, triage events, findings), so that two listeners of one purge cannot disagree about which issues it concerns.
/// In batches because a target's issues are sized by its history, and one bind parameter each is refused by the
/// PostgreSQL driver past 65,535.
///
/// **Read, then iterated, rather than Java's `inBatches(purge, action)`**: an action taking the deletion's `&mut Tx`
/// is an async closure, and a listener's boxed `Send` future cannot hold one that borrows anything — the compiler asks
/// the borrow to be `'static`. A loop over [`PurgedIssues::batches`] runs each batch in the purging transaction, one
/// after the other, as Java's does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgedIssues {
    ids: Vec<i64>,
}

impl PurgedIssues {
    /// The issues `purge` takes, read in `tx` — the deletion's.
    pub async fn of(tx: &mut Tx, purge: &TargetPurge) -> Result<PurgedIssues, StoreError> {
        Ok(PurgedIssues { ids: issues_of(tx, purge).await? })
    }

    /// At most [`PURGE_BATCH`] identifiers each.
    pub fn batches(&self) -> std::slice::Chunks<'_, i64> {
        self.ids.chunks(PURGE_BATCH)
    }

    /// How many there were — what `inBatches` answers.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
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
