//! `TicketSweepService`: the hourly pass that opens tickets and closes them.
//!
//! **A sweep, not an event**: the reference stored on the issue is the deduplication key, so a tracker under
//! maintenance is retried next pass instead of losing the ticket. **The gate decides, issue by issue**: a ticket is
//! opened for what the policy of the issue's scope would fail a build on. **Not one transaction for the pass**: each
//! issue is settled on its own, so a tracker that starts refusing at the twelfth does not undo the eleven opened.
//! **A suspended tracker is said once**, when the suspension begins and when it ends.

use std::sync::{Arc, Mutex};

use time::Duration;
use vectispire_cp_audit::{AuditLog, AuditOperation, Clock, Record};
use vectispire_cp_db::Db;
use vectispire_cp_gate::{
    ActiveGatePolicies, GateIssue, PolicyGate, PolicyLookup, PolicyResolution, PolicyScopeChoice, RequestedPolicy,
};
use vectispire_cp_issues::{IssueCatalog, IssueView};
use vectispire_domain::tickets::MAX_TICKETS_PER_SWEEP;
use vectispire_domain::triage_status::TriageStatus;

use crate::error::TicketError;
use vectispire_domain::tickets::TrackerState;

use crate::service::TicketService;

/// How long a claim holds: far longer than a tracker call, so it is only waited out when its instance died.
pub const CLAIM: Duration = Duration::minutes(10);

/// The sweep.
pub struct TicketSweepService {
    db: Db,
    issues: IssueCatalog,
    policies: ActiveGatePolicies,
    tickets: Arc<TicketService>,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock>,
    /// This process, as the holder of the claims it takes (V95).
    instance: String,
    /// The integration the last pass found suspended, empty when none: so that only a change is logged.
    suspension: Mutex<String>,
}

impl std::fmt::Debug for TicketSweepService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketSweepService").field("instance", &self.instance).finish_non_exhaustive()
    }
}

impl TicketSweepService {
    pub fn new(
        db: Db,
        issues: IssueCatalog,
        tickets: Arc<TicketService>,
        audit: Arc<AuditLog>,
        clock: Arc<dyn Clock>,
    ) -> TicketSweepService {
        TicketSweepService {
            policies: ActiveGatePolicies::new(db.clone()),
            db,
            issues,
            tickets,
            audit,
            clock,
            instance: uuid::Uuid::new_v4().simple().to_string(),
            suspension: Mutex::new(String::new()),
        }
    }

    /// One pass: how many tickets were opened and closed.
    pub async fn sweep(&self) -> Result<u32, TicketError> {
        self.sweep_at_most(MAX_TICKETS_PER_SWEEP).await
    }

    pub async fn sweep_at_most(&self, limit: u32) -> Result<u32, TicketError> {
        if self.suspended().await? || !self.tickets.is_enabled().await? {
            return Ok(0);
        }
        let created = self.open_actionable_tickets(limit).await?;
        let closed = self.close_resolved_tickets(limit).await?;
        Ok(created.saturating_add(closed))
    }

    async fn open_actionable_tickets(&self, limit: u32) -> Result<u32, TicketError> {
        // Every settled decision, an accepted risk's included: none of them is work to ticket.
        let excluded: Vec<String> = TriageStatus::settled_wire_names().iter().map(|name| (*name).to_owned()).collect();
        let candidates = self.issues.actionable_without_ticket("open", &excluded, u64::from(limit)).await?;
        if candidates.is_empty() {
            return Ok(0);
        }
        let by_scope = self.policies.by_scope().await.map_err(TicketError::failed)?;
        let names = vectispire_cp_targets::naming::all(&self.db).await.map_err(TicketError::failed)?;
        let mut created = 0u32;
        for issue in candidates {
            let resolved = PolicyResolution::resolve(
                PolicyLookup {
                    for_target: by_scope.get(&scope_of(&issue)).cloned(),
                    global: by_scope.get("global:0").cloned(),
                },
                &RequestedPolicy::none(),
                PolicyScopeChoice::Target,
            );
            // Below the bar: no ticket, and **no marker either** — tightened tomorrow, it is a candidate again.
            if PolicyGate::evaluate(
                &[GateIssue::of_view(&issue)],
                &resolved.policy,
                &vectispire_cp_gate::Coverage::NOT_APPLICABLE,
                None,
            )
            .passed
            {
                continue;
            }
            // **Claimed before the tracker is asked**: every instance runs this sweep, and a tracker does not
            // deduplicate.
            let now = self.clock.now();
            if !self.issues.claim_ticket(issue.id, &self.instance, now, now.saturating_add(CLAIM)).await? {
                continue;
            }
            let target = names.of(issue.repo_id, issue.container_id);
            let Some(ticket) = self.tickets.create_for_issue(&issue.for_ticket(), &target).await else {
                // Left without a reference on purpose, and the claim given up: the next pass tries again.
                self.issues.release_ticket_claim(issue.id, &self.instance).await?;
                continue;
            };
            created = created.saturating_add(1);
            // **Only onto an issue that still carries no reference**: one a person attached meanwhile is kept.
            let recorded = self.issues.attach_ticket(issue.id, &ticket.reference, Some(&ticket.url)).await? == 1;
            if !recorded {
                self.issues.release_ticket_claim(issue.id, &self.instance).await?;
                tracing::warn!(
                    "Ticket {} was opened on the tracker for issue {}, which carries another reference attached \
                     meanwhile: the new ticket is not recorded on the issue and may need closing by hand.",
                    one_line(&ticket.reference),
                    issue.id
                );
            }
            let subject = if issue.identifier.is_empty() { issue.type_.as_str() } else { issue.identifier.as_str() };
            self.audit
                .record(Record::of(
                    AuditOperation::TicketCreated,
                    &issue.id.to_string(),
                    &format!(
                        "Ticket {} opened for {subject} ({}){}",
                        ticket.reference,
                        resolved.describe_source(),
                        if recorded {
                            ""
                        } else {
                            "; not recorded on the issue, which carries a reference attached meanwhile"
                        }
                    ),
                    None,
                ))
                .await;
        }
        if created > 0 {
            tracing::info!("{created} ticket(s) opened.");
        }
        Ok(created)
    }

    /// Closes on the tracker the tickets of issues marked resolved — only those Vectispire opened.
    pub async fn close_resolved_tickets(&self, limit: u32) -> Result<u32, TicketError> {
        let resolved = self.issues.resolved_with_open_ticket(u64::from(limit)).await?;
        let mut closed = 0u32;
        for issue in resolved {
            if !self.tickets.close_ticket(issue.ticket_ref.as_deref(), "Resolved by clean security scan").await {
                continue;
            }
            let reference = issue.ticket_ref.clone().unwrap_or_default();
            if self.issues.mark_ticket_closed(issue.id, &reference).await? == 0 {
                tracing::warn!(
                    "Ticket {} was closed on the tracker, but issue {} now carries another reference: left as it is.",
                    one_line(&reference),
                    issue.id
                );
            }
            closed = closed.saturating_add(1);
            self.audit
                .record(Record::of(
                    AuditOperation::TicketClosed,
                    &issue.id.to_string(),
                    &format!("Ticket {reference} automatically closed after issue resolution"),
                    None,
                ))
                .await;
        }
        if closed > 0 {
            tracing::info!("{closed} resolved ticket(s) automatically closed on tracker.");
        }
        Ok(closed)
    }

    /// Whether the configured tracker is suspended, logged when that changes since the last pass.
    async fn suspended(&self) -> Result<bool, TicketError> {
        let now = self
            .tickets
            .standing()
            .await?
            .filter(|standing| standing.state == TrackerState::Suspended)
            .map(|standing| standing.integration.key())
            .unwrap_or_default();
        let before = {
            let mut last = self.suspension.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *last, now.clone())
        };
        if now != before {
            if !now.is_empty() {
                tracing::info!(
                    "Ticket sweep: the {now} integration is disabled. No ticket is opened or closed, and nothing is sent \
                     to the tracker; its token, its settings and the issues' tickets are kept, and the sweep resumes \
                     when a platform governor re-enables it."
                );
            } else if !before.is_empty() {
                tracing::info!(
                    "Ticket sweep: the {before} integration is enabled again; tickets are opened and closed again."
                );
            }
        }
        Ok(!now.is_empty())
    }
}

/// An issue with neither target falls back on the global policy rather than resolving `container:null`.
fn scope_of(issue: &IssueView) -> String {
    match (issue.repo_id, issue.container_id) {
        (Some(repository), _) => format!("repository:{repository}"),
        (None, Some(container)) => format!("container:{container}"),
        (None, None) => "global:0".to_owned(),
    }
}

/// `LogText.of`: a tracker's text in a log line, its line breaks unable to forge a second entry.
pub(crate) fn one_line(value: &str) -> String {
    value.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}
