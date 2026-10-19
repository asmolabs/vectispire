//! Human decisions on issues: triage, bulk triage, and ticket attachment.

use std::sync::Arc;

use vectispire_cp_audit::{AuditLog, AuditOperation, Record};
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_settings::{Setting, Settings};

use crate::error::IssueError;
use crate::persistence::IssueRepository;
use crate::triage::{IssueTriageService, TriageRequest, TriageStatus, VexJustification};
use crate::views::IssueView;

/// Who is deciding, what they may see, and where the request came from.
#[derive(Debug, Clone)]
pub struct Caller {
    pub username: Option<String>,
    pub role: Option<vectispire_cp_http::Role>,
    pub visibility: Visibility,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl Caller {
    pub fn actor(&self) -> String {
        self.username.clone().unwrap_or_else(|| "unknown".to_owned())
    }
}

/// A triage decision as the request spells it.
#[derive(Debug, Clone)]
pub struct Decision {
    pub status: Option<String>,
    pub justification: Option<String>,
    pub comment: Option<String>,
    pub expires_in_days: Option<i64>,
}

impl Decision {
    pub fn to_request(&self, actor: String) -> TriageRequest {
        TriageRequest {
            status: self.status.as_deref().and_then(TriageStatus::from_wire_name),
            actor: Some(actor),
            justification: self.justification.as_deref().and_then(VexJustification::from_wire_name),
            comment: self.comment.clone(),
            expires_in_days: self.expires_in_days,
        }
    }
}

pub struct IssueDecisionService {
    db: Db,
    settings: Arc<Settings>,
    audit: Arc<AuditLog>,
}

impl IssueDecisionService {
    pub const MAX_BULK_TRIAGE: usize = 500;
    pub const MAX_TICKET_REFERENCE: usize = 64;
    pub const MAX_TICKET_URL: usize = 500;

    pub fn new(db: Db, settings: Arc<Settings>, audit: Arc<AuditLog>) -> Self {
        Self { db, settings, audit }
    }

    /// Records one triage decision.
    pub async fn triage(&self, id: i64, decision: Decision, caller: Caller) -> Result<IssueView, IssueError> {
        let actor = caller.actor();
        let can_approve = self.can_approve(&caller).await;

        let mut tx = crate::persistence::write(&self.db).await?;

        // Check visibility first
        let issue = IssueRepository::find_by_id(&mut tx, id)
            .await?
            .ok_or_else(|| IssueError::NotFound(format!("Issue {id} not found.")))?;

        Self::require_visible(&issue, &caller.visibility)?;
        let _previous = issue.triage_status.clone();

        let request = decision.to_request(actor.clone());
        let updated = IssueTriageService::triage(&mut tx, id, &request, can_approve).await?;
        crate::persistence::commit(tx).await?;

        // Audit log
        let desc = format!(
            "Triage \"{}\"{}{}",
            updated.triage_status,
            match &updated.triage_requested_status {
                Some(req) => format!(" asking for \"{req}\""),
                None => String::new(),
            },
            match &updated.triage_justification {
                Some(just) => format!(" ({just})"),
                None => String::new(),
            }
        );

        let mut rec = Record::of(AuditOperation::IssueTriaged, &id.to_string(), &desc, Some(&actor));
        rec.ip_address = caller.ip_address;
        rec.user_agent = caller.user_agent;
        self.audit.record(rec).await;

        Ok(updated.to_view())
    }

    /// The same decision on many issues.
    pub async fn triage_many(
        &self,
        ids: &[i64],
        decision: Decision,
        caller: Caller,
    ) -> Result<Vec<IssueView>, IssueError> {
        if ids.is_empty() {
            return Err(IssueError::InvalidTriage("Select at least one issue to triage.".to_owned()));
        }
        if ids.len() > Self::MAX_BULK_TRIAGE {
            return Err(IssueError::InvalidTriage(format!(
                "Too many issues at once: {}, the limit is {}.",
                ids.len(),
                Self::MAX_BULK_TRIAGE
            )));
        }

        let actor = caller.actor();
        let can_approve = self.can_approve(&caller).await;

        let mut tx = crate::persistence::write(&self.db).await?;
        let request = decision.to_request(actor.clone());
        let result =
            IssueTriageService::triage_visible(&mut tx, ids, &request, can_approve, &caller.visibility).await?;
        crate::persistence::commit(tx).await?;

        // One audit entry for bulk triage
        let desc = format!(
            "Bulk triage \"{}\" on {} issues{} — per-issue transitions are in each issue's triage history",
            decision.status.as_deref().unwrap_or(""),
            ids.len(),
            match &decision.justification {
                Some(just) => format!(" ({just})"),
                None => String::new(),
            }
        );

        let mut rec = Record::of(AuditOperation::IssueTriaged, &format!("{} issues", ids.len()), &desc, Some(&actor));
        rec.ip_address = caller.ip_address;
        rec.user_agent = caller.user_agent;
        self.audit.record(rec).await;

        Ok(result.triaged.into_iter().map(|i| i.to_view()).collect())
    }

    /// Attaches an existing ticket to a finding.
    pub async fn attach_ticket(
        &self,
        id: i64,
        raw_reference: Option<String>,
        raw_url: Option<String>,
        caller: Caller,
    ) -> Result<IssueView, IssueError> {
        let reference = raw_reference
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| IssueError::InvalidInput("A ticket reference is required.".to_owned()))?;

        if reference.len() > Self::MAX_TICKET_REFERENCE {
            return Err(IssueError::InvalidInput(format!(
                "That reference is longer than {} characters.",
                Self::MAX_TICKET_REFERENCE
            )));
        }

        let url = raw_url.as_deref().map(str::trim).filter(|s| !s.is_empty());

        if let Some(u) = url
            && u.len() > Self::MAX_TICKET_URL
        {
            return Err(IssueError::InvalidInput(format!(
                "That URL is longer than {} characters.",
                Self::MAX_TICKET_URL
            )));
        }

        let actor = caller.actor();
        let mut tx = crate::persistence::write(&self.db).await?;

        let mut issue = IssueRepository::find_by_id(&mut tx, id)
            .await?
            .ok_or_else(|| IssueError::NotFound(format!("Issue {id} not found.")))?;

        Self::require_visible(&issue, &caller.visibility)?;

        let previous_ticket = issue.ticket_ref.clone();
        issue.ticket_ref = Some(reference.to_owned());
        issue.ticket_url = url.map(str::to_owned);
        issue.ticket_attached_by = Some(actor.clone());

        let updated = IssueRepository::update_issue(&mut tx, &issue).await?;
        if !updated {
            return Err(IssueError::ChangedMeanwhile);
        }
        crate::persistence::commit(tx).await?;

        let desc = match previous_ticket {
            Some(prev) => format!("Ticket reference changed from {prev} to {reference}"),
            None => format!("Ticket {reference} attached"),
        };

        let mut rec = Record::of(AuditOperation::IssueTriaged, &id.to_string(), &desc, Some(&actor));
        rec.ip_address = caller.ip_address;
        rec.user_agent = caller.user_agent;
        self.audit.record(rec).await;

        let refreshed = self.find_by_id(id).await?;
        Ok(refreshed)
    }

    async fn find_by_id(&self, id: i64) -> Result<IssueView, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let issue = IssueRepository::find_by_id(&mut tx, id)
            .await?
            .ok_or_else(|| IssueError::NotFound(format!("Issue {id} not found.")))?;
        Ok(issue.to_view())
    }

    fn require_visible(issue: &crate::persistence::IssueRow, visibility: &Visibility) -> Result<(), IssueError> {
        let target = match (issue.repo_id, issue.container_id) {
            (Some(repo_id), _) => ScanTarget::Repository(repo_id),
            (None, Some(container_id)) => ScanTarget::Container(container_id),
            (None, None) => {
                if !matches!(visibility, Visibility::Everything) {
                    return Err(IssueError::NotFound(format!("Issue {} not found.", issue.id)));
                }
                return Ok(());
            }
        };

        if !visibility.permits(target) {
            return Err(IssueError::NotFound(format!("Issue {} not found.", issue.id)));
        }
        Ok(())
    }

    async fn can_approve(&self, caller: &Caller) -> bool {
        let four_eyes_required = self.settings.is_enabled(Setting::FourEyesApprovalRequired).await.unwrap_or(false);

        if !four_eyes_required {
            return true;
        }

        caller.role.map(|r| r.can_approve_triage()).unwrap_or(true)
    }
}

opaque_debug!(IssueDecisionService);
