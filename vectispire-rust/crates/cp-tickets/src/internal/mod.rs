//! The module's maintenance tasks, the issues' reference port and the purge listener — what other modules call
//! without naming a service.

use std::sync::Arc;

use vectispire_cp_db::Tx;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_issues::purge::PurgedIssues;
use vectispire_cp_issues::{TicketReferenceError, TicketReferences};
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};
use vectispire_cp_targets::TargetPurge;
use vectispire_cp_targets::deletion::{ListenerName, Phase, PurgeError, PurgeListener};
use vectispire_domain::tickets::{self, TicketProvider, TrackerState};

use crate::persistence;
use crate::service::TicketService;
use crate::sweep::TicketSweepService;

/// The ticket sweep, hourly: idempotent, so a tracker under maintenance is retried next turn.
#[derive(Debug)]
pub struct TicketSweepTask(pub Arc<TicketSweepService>);

impl MaintenanceTask for TicketSweepTask {
    fn sequence(&self) -> Sequence {
        Sequence::TicketSweep
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            self.0.sweep().await?;
            Ok(())
        })
    }
}

/// The tracker token's check: asked daily, counted from the tracker's last answer; announced on the hour.
#[derive(Debug)]
pub struct TicketTokenCheckTask(pub Arc<TicketService>);

impl MaintenanceTask for TicketTokenCheckTask {
    fn sequence(&self) -> Sequence {
        Sequence::TicketTokenCheck
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            self.0.check_token_if_due().await;
            Ok(())
        })
    }
}

/// `TrackerTicketReferences`: a reference the configured tracker issues, in the project Vectispire files into — and
/// none onto a suspended tracker, whose synchronisation the switch stopped.
#[derive(Debug)]
pub struct TrackerTicketReferences(pub Arc<TicketService>);

impl TicketReferences for TrackerTicketReferences {
    fn refusal<'a>(&'a self, reference: &'a str) -> BoxFuture<'a, Result<Option<String>, TicketReferenceError>> {
        Box::pin(async move {
            let failed = |error: crate::TicketError| TicketReferenceError::Failed(error.to_string());
            if let Some(standing) = self.0.standing().await.map_err(failed)?
                && standing.state == TrackerState::Suspended
            {
                return Err(TicketReferenceError::IntegrationDisabled(standing.integration));
            }
            let provider = self.0.provider().await.map_err(failed)?;
            let project = self.0.project().await.map_err(failed)?;
            if provider == TicketProvider::None
                || tickets::reference_path(provider, Some(reference), Some(&project)).is_some()
            {
                return Ok(None);
            }
            let in_project = if provider == TicketProvider::Jira && !vectispire_domain::java::is_blank(&project) {
                format!(" in project {project}")
            } else {
                String::new()
            };
            Ok(Some(format!("\"{reference}\" is not a {} reference{in_project}.", provider.wire_name())))
        })
    }
}

/// `TicketLinkPurge`: the links of a purged target's issues, before the issues — only the links: the tickets live in
/// the tracker, and closing them on a deletion was never this product's decision.
#[derive(Debug, Clone, Copy, Default)]
pub struct TicketLinkPurge;

impl PurgeListener for TicketLinkPurge {
    fn name(&self) -> ListenerName {
        ListenerName { module: "tickets", listener: "TicketLinkPurge.purge" }
    }

    fn phase(&self) -> Phase {
        Phase::IssueChildren
    }

    fn purge<'a>(&'a self, tx: &'a mut Tx, purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async move {
            let purged = PurgedIssues::of(tx, purge).await?;
            for batch in purged.batches() {
                persistence::delete_of_issues(tx, batch).await?;
            }
            Ok(())
        })
    }
}
