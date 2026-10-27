//! Triage statuses, VEX justifications, rules, and service transitions.

use time::{Duration, OffsetDateTime};
use vectispire_cp_db::{Db, ScanTarget, Tx, Visibility};
use vectispire_domain::bounded_text;

use crate::error::IssueError;
use crate::persistence::{IssueRepository, IssueRow, NewTriageEvent};

/// Where an issue stands with humans — the domain crate's, which the SIEM's triage signals read too.
pub use vectispire_domain::triage_status::TriageStatus;

/// The justifications a `not_affected` statement may carry (OpenVEX / CSAF).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexJustification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
}

impl VexJustification {
    pub fn wire_name(&self) -> &'static str {
        match self {
            VexJustification::ComponentNotPresent => "component_not_present",
            VexJustification::VulnerableCodeNotPresent => "vulnerable_code_not_present",
            VexJustification::VulnerableCodeNotInExecutePath => "vulnerable_code_not_in_execute_path",
            VexJustification::VulnerableCodeCannotBeControlledByAdversary => {
                "vulnerable_code_cannot_be_controlled_by_adversary"
            }
            VexJustification::InlineMitigationsAlreadyExist => "inline_mitigations_already_exist",
        }
    }

    pub fn from_wire_name(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "component_not_present" => Some(VexJustification::ComponentNotPresent),
            "vulnerable_code_not_present" => Some(VexJustification::VulnerableCodeNotPresent),
            "vulnerable_code_not_in_execute_path" => Some(VexJustification::VulnerableCodeNotInExecutePath),
            "vulnerable_code_cannot_be_controlled_by_adversary" => {
                Some(VexJustification::VulnerableCodeCannotBeControlledByAdversary)
            }
            "inline_mitigations_already_exist" => Some(VexJustification::InlineMitigationsAlreadyExist),
            _ => None,
        }
    }
}

/// What wrote an entry of an issue's triage history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageOrigin {
    Manual,
    Approval,
    Expiry,
    Review,
    Reopening,
}

impl TriageOrigin {
    pub fn wire_name(&self) -> &'static str {
        match self {
            TriageOrigin::Manual => "manual",
            TriageOrigin::Approval => "approval",
            TriageOrigin::Expiry => "expiry",
            TriageOrigin::Review => "review",
            TriageOrigin::Reopening => "reopen",
        }
    }
}

/// What a reviewer concluded about an exception they were asked to look at again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewOutcome {
    Confirmed,
    Extended,
    Revoked,
}

impl ReviewOutcome {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "CONFIRMED" => Some(ReviewOutcome::Confirmed),
            "EXTENDED" => Some(ReviewOutcome::Extended),
            "REVOKED" => Some(ReviewOutcome::Revoked),
            _ => None,
        }
    }
}

/// Pure domain triage rules and validation.
pub struct Triage;

#[derive(Debug, Clone)]
pub struct TriageRequest {
    pub status: Option<TriageStatus>,
    pub actor: Option<String>,
    pub justification: Option<VexJustification>,
    pub comment: Option<String>,
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct TriageDecision {
    pub status: TriageStatus,
    pub justification: Option<VexJustification>,
    pub comment: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
}

impl Triage {
    pub const MAX_REVIEW_DAYS: i64 = 3650;
    /// Java's `Triage.MAX_COMMENT_LENGTH`, which is `BoundedText.TEXT_MAX`: it was 10,000 here, and a 12,000-character comment
    /// Java stores was refused.
    pub const MAX_COMMENT_LENGTH: usize = bounded_text::TEXT_MAX;

    pub fn decide(request: &TriageRequest, as_of: OffsetDateTime) -> Result<TriageDecision, IssueError> {
        let status =
            request.status.ok_or_else(|| IssueError::InvalidTriage("A triage decision needs a status.".to_owned()))?;

        if (status == TriageStatus::NotAffected || status == TriageStatus::PendingApproval)
            && request.justification.is_none()
        {
            return Err(IssueError::InvalidTriage(
                "A justification is required for this triage status (VEX requirement).".to_owned(),
            ));
        }

        if status == TriageStatus::WillNotFix {
            if request.justification.is_some() {
                return Err(IssueError::InvalidTriage(
                    "A risk accepted carries no VEX justification: it is not an argument that the product is not affected.".to_owned(),
                ));
            }
            if request.expires_in_days.is_none() {
                return Err(IssueError::InvalidTriage("A risk accepted needs a review date.".to_owned()));
            }
        }

        // In UTF-16 units, as Java's `String.length`: `len()` counted bytes, and 9,000 accented letters Java stores were refused.
        if let Some(refused) =
            bounded_text::too_long(request.comment.as_deref(), Self::MAX_COMMENT_LENGTH, "The comment")
        {
            return Err(IssueError::InvalidTriage(refused));
        }

        let expires_at = Self::expiry_from(status, request.expires_in_days, as_of)?;

        Ok(TriageDecision {
            status,
            justification: request.justification,
            comment: request.comment.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned),
            triaged_by: request.actor.clone(),
            triaged_at: as_of,
            expires_at,
        })
    }

    pub fn expiry_from(
        status: TriageStatus,
        expires_in_days: Option<i64>,
        as_of: OffsetDateTime,
    ) -> Result<Option<OffsetDateTime>, IssueError> {
        if status == TriageStatus::UnderReview || expires_in_days.is_none() {
            return Ok(None);
        }
        let days = expires_in_days.unwrap_or_default();
        if days <= 0 {
            return Err(IssueError::InvalidTriage("The review delay must be at least one day.".to_owned()));
        }
        if days > Self::MAX_REVIEW_DAYS {
            return Err(IssueError::InvalidTriage(format!(
                "The review delay is at most {} days. Leave it empty for no review date.",
                Self::MAX_REVIEW_DAYS
            )));
        }
        Ok(Some(as_of.saturating_add(Duration::days(days))))
    }

    pub fn is_expired(status: &str, expires_at: Option<OffsetDateTime>, as_of: OffsetDateTime) -> bool {
        if status == TriageStatus::UnderReview.wire_name() {
            return false;
        }
        match expires_at {
            Some(exp) => as_of >= exp,
            None => false,
        }
    }

    pub fn expire() -> (&'static str, Option<OffsetDateTime>) {
        (TriageStatus::UnderReview.wire_name(), None)
    }
}

pub struct BulkTriageResult {
    pub previous: Vec<String>,
    pub triaged: Vec<IssueRow>,
}

/// Service handling database triage transitions.
#[derive(Clone)]
pub struct IssueTriageService {
    db: Db,
}

impl IssueTriageService {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Helper to queue decisions for approval if maker cannot approve.
    fn queue_if_not_approver(decision: TriageDecision, can_approve: bool) -> (TriageDecision, Option<String>) {
        if can_approve || !decision.status.is_settled() {
            (decision, None)
        } else {
            let requested = Some(decision.status.wire_name().to_owned());
            let queued = TriageDecision {
                status: TriageStatus::PendingApproval,
                justification: decision.justification,
                comment: decision.comment,
                triaged_by: decision.triaged_by,
                triaged_at: decision.triaged_at,
                expires_at: decision.expires_at,
            };
            (queued, requested)
        }
    }

    /// Single issue triage.
    pub async fn triage(
        tx: &mut Tx,
        issue_id: i64,
        request: &TriageRequest,
        can_approve: bool,
    ) -> Result<IssueRow, IssueError> {
        let now = OffsetDateTime::now_utc();
        let decision = Triage::decide(request, now)?;
        let (decision, requested) = Self::queue_if_not_approver(decision, can_approve);

        let mut issue = IssueRepository::find_by_id(tx, issue_id)
            .await?
            .ok_or_else(|| IssueError::NotFound("Issue not found.".to_owned()))?;

        let previous = issue.triage_status.clone();
        let origin = if previous == TriageStatus::PendingApproval.wire_name() && decision.status.is_settled() {
            TriageOrigin::Approval.wire_name()
        } else {
            TriageOrigin::Manual.wire_name()
        };

        if origin == TriageOrigin::Approval.wire_name() {
            Self::require_a_second_pair_of_eyes(tx, issue.id, decision.triaged_by.as_deref()).await?;
            if let Some(req) = &issue.triage_requested_status
                && req != decision.status.wire_name()
            {
                return Err(IssueError::ApprovalDiffers {
                    requested_status: req.clone(),
                    actual_status: decision.status.wire_name().to_owned(),
                });
            }
        }

        issue.triage_status = decision.status.wire_name().to_owned();
        issue.triage_justification = decision.justification.map(|j| j.wire_name().to_owned());
        issue.triage_comment = decision.comment.clone();
        issue.triaged_by = decision.triaged_by.clone();
        issue.triaged_at = Some(decision.triaged_at);
        issue.triage_expires_at = decision.expires_at;
        issue.triage_requested_status = requested.clone();

        let updated = IssueRepository::update_issue(tx, &issue).await?;
        if !updated {
            return Err(IssueError::ChangedMeanwhile);
        }

        let event = NewTriageEvent {
            issue_id: issue.id,
            from_status: previous,
            to_status: decision.status.wire_name().to_owned(),
            justification: decision.justification.map(|j| j.wire_name().to_owned()),
            comment: decision.comment,
            actor: decision.triaged_by,
            origin: origin.to_owned(),
            occurred_at: decision.triaged_at,
            expires_at: decision.expires_at,
            scan_id: issue.last_seen_scan_id,
            previous_resolved_at: None,
            requested_status: requested,
        };
        IssueRepository::insert_triage_events(tx, &[event]).await?;

        // Re-read with incremented revision
        let refreshed = IssueRepository::find_by_id(tx, issue_id)
            .await?
            .ok_or_else(|| IssueError::NotFound("Issue not found.".to_owned()))?;
        Ok(refreshed)
    }

    /// Bulk issue triage with visibility checking.
    pub async fn triage_visible(
        tx: &mut Tx,
        issue_ids: &[i64],
        request: &TriageRequest,
        can_approve: bool,
        visibility: &Visibility,
    ) -> Result<BulkTriageResult, IssueError> {
        let now = OffsetDateTime::now_utc();
        let decision = Triage::decide(request, now)?;
        let (decision, requested) = Self::queue_if_not_approver(decision, can_approve);

        let issues = IssueRepository::find_by_ids(tx, issue_ids).await?;
        let issue_map: std::collections::BTreeMap<i64, IssueRow> = issues.into_iter().map(|i| (i.id, i)).collect();

        // 1. Verify all issues exist and are visible
        let mut ordered_existing = Vec::with_capacity(issue_ids.len());
        let mut previous_statuses = Vec::with_capacity(issue_ids.len());

        for &id in issue_ids {
            let row = issue_map.get(&id).ok_or_else(|| IssueError::NotFound("Issue not found.".to_owned()))?;

            let target = match (row.repo_id, row.container_id) {
                (Some(repo_id), _) => ScanTarget::Repository(repo_id),
                (None, Some(container_id)) => ScanTarget::Container(container_id),
                (None, None) => {
                    if !matches!(visibility, Visibility::Everything) {
                        return Err(IssueError::NotFound("Issue not found.".to_owned()));
                    }
                    ordered_existing.push(row.clone());
                    previous_statuses.push(row.triage_status.clone());
                    continue;
                }
            };

            if !visibility.permits(target) {
                return Err(IssueError::NotFound("Issue not found.".to_owned()));
            }

            ordered_existing.push(row.clone());
            previous_statuses.push(row.triage_status.clone());
        }

        // 2. Perform updates
        let mut triaged_rows = Vec::with_capacity(ordered_existing.len());
        let mut new_events = Vec::with_capacity(ordered_existing.len());

        for mut row in ordered_existing {
            let previous = row.triage_status.clone();
            let origin = if previous == TriageStatus::PendingApproval.wire_name() && decision.status.is_settled() {
                TriageOrigin::Approval.wire_name()
            } else {
                TriageOrigin::Manual.wire_name()
            };

            if origin == TriageOrigin::Approval.wire_name() {
                Self::require_a_second_pair_of_eyes(tx, row.id, decision.triaged_by.as_deref()).await?;
                if let Some(req) = &row.triage_requested_status
                    && req != decision.status.wire_name()
                {
                    return Err(IssueError::ApprovalDiffers {
                        requested_status: req.clone(),
                        actual_status: decision.status.wire_name().to_owned(),
                    });
                }
            }

            row.triage_status = decision.status.wire_name().to_owned();
            row.triage_justification = decision.justification.map(|j| j.wire_name().to_owned());
            row.triage_comment = decision.comment.clone();
            row.triaged_by = decision.triaged_by.clone();
            row.triaged_at = Some(decision.triaged_at);
            row.triage_expires_at = decision.expires_at;
            row.triage_requested_status = requested.clone();

            let updated = IssueRepository::update_issue(tx, &row).await?;
            if !updated {
                return Err(IssueError::ChangedMeanwhile);
            }

            new_events.push(NewTriageEvent {
                issue_id: row.id,
                from_status: previous,
                to_status: decision.status.wire_name().to_owned(),
                justification: decision.justification.map(|j| j.wire_name().to_owned()),
                comment: decision.comment.clone(),
                actor: decision.triaged_by.clone(),
                origin: origin.to_owned(),
                occurred_at: decision.triaged_at,
                expires_at: decision.expires_at,
                scan_id: row.last_seen_scan_id,
                previous_resolved_at: None,
                requested_status: requested.clone(),
            });

            // Revision bumped by 1
            row.revision = row.revision.saturating_add(1);
            triaged_rows.push(row);
        }

        if !new_events.is_empty() {
            IssueRepository::insert_triage_events(tx, &new_events).await?;
        }

        Ok(BulkTriageResult { previous: previous_statuses, triaged: triaged_rows })
    }

    /// Checks that the person approving did not request the exemption.
    async fn require_a_second_pair_of_eyes(
        tx: &mut Tx,
        issue_id: i64,
        approver: Option<&str>,
    ) -> Result<(), IssueError> {
        let events = IssueRepository::find_triage_events_by_issue_id(tx, issue_id).await?;
        let mut requester: Option<String> = None;
        for ev in events {
            if ev.to_status == TriageStatus::PendingApproval.wire_name() {
                requester = ev.actor;
            }
        }

        if let Some(req) = requester {
            let req_clean = req.trim();
            if !req_clean.is_empty()
                && let Some(app) = approver
                && req_clean.eq_ignore_ascii_case(app.trim())
            {
                return Err(IssueError::InvalidTriage(format!(
                    "Four-eyes approval: this exemption was requested by {req_clean}, so it has to be approved by somebody else."
                )));
            }
        }
        Ok(())
    }

    /// Periodic review of an exception.
    pub async fn review(
        tx: &mut Tx,
        issue_id: i64,
        outcome: ReviewOutcome,
        comment: Option<String>,
        actor: Option<String>,
        new_expiry: Option<OffsetDateTime>,
    ) -> Result<IssueRow, IssueError> {
        if let Some(refused) = bounded_text::too_long(comment.as_deref(), Triage::MAX_COMMENT_LENGTH, "The comment") {
            return Err(IssueError::InvalidInput(refused));
        }

        let mut issue = IssueRepository::find_by_id(tx, issue_id)
            .await?
            .ok_or_else(|| IssueError::InvalidInput(format!("No such issue: {issue_id}")))?;

        let current = TriageStatus::from_wire_name(&issue.triage_status);
        if !matches!(
            current,
            Some(TriageStatus::NotAffected) | Some(TriageStatus::WillNotFix) | Some(TriageStatus::PendingApproval)
        ) {
            return Err(IssueError::InvalidInput("Nothing to review: this issue carries no exception.".to_owned()));
        }

        let now = OffsetDateTime::now_utc();
        if outcome == ReviewOutcome::Extended {
            let Some(exp) = new_expiry else {
                return Err(IssueError::InvalidInput(
                    "Extending an exception needs the date it now runs to.".to_owned(),
                ));
            };
            if exp <= now {
                return Err(IssueError::InvalidInput("An extension runs to a date in the future.".to_owned()));
            }
            let max_review = now.saturating_add(Duration::days(Triage::MAX_REVIEW_DAYS));
            if exp > max_review {
                return Err(IssueError::InvalidInput(format!(
                    "An extension runs at most {} days from today.",
                    Triage::MAX_REVIEW_DAYS
                )));
            }
        }

        let from_status = issue.triage_status.clone();
        let mut to_status = from_status.clone();

        let unchanged = issue.clone();
        match outcome {
            ReviewOutcome::Confirmed => {}
            ReviewOutcome::Extended => {
                issue.triage_expires_at = new_expiry;
            }
            ReviewOutcome::Revoked => {
                to_status = TriageStatus::UnderReview.wire_name().to_owned();
                issue.triage_status = to_status.clone();
                issue.triage_expires_at = None;
                issue.triage_requested_status = None;
            }
        }

        // Written only when the review changed it, as Hibernate writes an entity only when it is dirty: a confirmation —
        // the review that leaves the decision as it was — moved the issue's revision, and a client holding it was told
        // the issue had changed meanwhile when nothing had. The review itself is the event below, whatever the outcome.
        if issue != unchanged && !IssueRepository::update_issue(tx, &issue).await? {
            return Err(IssueError::ChangedMeanwhile);
        }

        let event = NewTriageEvent {
            issue_id: issue.id,
            from_status,
            to_status,
            justification: issue.triage_justification.clone(),
            comment,
            actor,
            origin: TriageOrigin::Review.wire_name().to_owned(),
            occurred_at: now,
            expires_at: issue.triage_expires_at,
            scan_id: issue.last_seen_scan_id,
            previous_resolved_at: None,
            requested_status: None,
        };
        IssueRepository::insert_triage_events(tx, &[event]).await?;

        let refreshed = IssueRepository::find_by_id(tx, issue_id)
            .await?
            .ok_or_else(|| IssueError::NotFound("Issue not found.".to_owned()))?;
        Ok(refreshed)
    }

    /// Expires stale triage decisions past their review date.
    pub async fn expire_stale(tx: &mut Tx, now: OffsetDateTime) -> Result<Vec<i64>, IssueError> {
        let due = IssueRepository::find_with_expired_triage(tx, now).await?;
        let mut expired = Vec::new();
        let mut events_to_add = Vec::new();

        for mut issue in due {
            if !Triage::is_expired(&issue.triage_status, issue.triage_expires_at, now) {
                continue;
            }
            let (new_status, new_expires) = Triage::expire();
            let prev = issue.triage_status.clone();
            issue.triage_status = new_status.to_owned();
            issue.triage_expires_at = new_expires;
            issue.triage_requested_status = None;

            let updated = IssueRepository::update_issue(tx, &issue).await?;
            if !updated {
                continue;
            }

            expired.push(issue.id);
            events_to_add.push(NewTriageEvent {
                issue_id: issue.id,
                from_status: prev,
                to_status: new_status.to_owned(),
                justification: issue.triage_justification,
                comment: None,
                actor: None,
                origin: TriageOrigin::Expiry.wire_name().to_owned(),
                occurred_at: now,
                expires_at: new_expires,
                scan_id: issue.last_seen_scan_id,
                previous_resolved_at: None,
                requested_status: None,
            });
        }

        if !events_to_add.is_empty() {
            IssueRepository::insert_triage_events(tx, &events_to_add).await?;
        }

        Ok(expired)
    }

    /// Convenience method for maintenance tasks that opens a write transaction and expires stale triage decisions as of now.
    pub async fn expire_stale_now(&self) -> Result<Vec<i64>, IssueError> {
        let mut tx = crate::persistence::write(&self.db).await?;
        let now = OffsetDateTime::now_utc();
        let expired = Self::expire_stale(&mut tx, now).await?;
        crate::persistence::commit(tx).await?;
        Ok(expired)
    }

    /// Convenience method for exception reviews that opens a write transaction and applies the review.
    pub async fn review_now(
        &self,
        issue_id: i64,
        outcome: ReviewOutcome,
        comment: Option<String>,
        actor: Option<String>,
        new_expiry: Option<OffsetDateTime>,
    ) -> Result<IssueRow, IssueError> {
        let mut tx = crate::persistence::write(&self.db).await?;
        let row = Self::review(&mut tx, issue_id, outcome, comment, actor, new_expiry).await?;
        crate::persistence::commit(tx).await?;
        Ok(row)
    }
}

opaque_debug!(Triage, BulkTriageResult, IssueTriageService);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn commented(comment: String) -> TriageRequest {
        TriageRequest {
            status: Some(TriageStatus::Affected),
            actor: Some("alice".to_owned()),
            justification: None,
            comment: Some(comment),
            expires_in_days: None,
        }
    }

    #[test]
    fn a_comment_is_held_to_java_s_ceiling_in_utf16_units() {
        let now = OffsetDateTime::now_utc();
        // Java's BoundedText.TEXT_MAX: 12,000 characters were refused at the old 10,000.
        assert!(Triage::decide(&commented("a".repeat(16_000)), now).is_ok());
        let Err(IssueError::InvalidTriage(refused)) = Triage::decide(&commented("a".repeat(16_001)), now) else {
            panic!("16,001 units must be refused");
        };
        assert_eq!(refused, "The comment is longer than 16000 characters.");
        // 16,000 units, 32,000 bytes: Java stores it, a count in bytes refused it.
        assert!(Triage::decide(&commented("é".repeat(16_000)), now).is_ok());
        // An astral character is two units, as String.length counts it.
        assert!(Triage::decide(&commented("😀".repeat(8_001)), now).is_err());
    }
}
