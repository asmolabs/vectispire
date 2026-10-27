//! Exceptions register and periodic review service.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_http::Role;
use vectispire_cp_targets::naming;

use crate::error::IssueError;
use crate::persistence::{IssueRepository, IssueRow, TriageEventRepository, TriageEventRow};
use crate::triage::{IssueTriageService, ReviewOutcome};

pub const MAX_ENTRIES: usize = 500;
pub const REGISTER_AFTER_REVIEW: usize = 200;

const REVIEW_ORIGIN: &str = "review";
const REOPEN_ORIGIN: &str = "reopen";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExceptionEntry {
    #[serde(rename = "issue_id")]
    pub issue_id: i64,
    pub identifier: String,
    pub severity: String,
    #[serde(rename = "target_kind")]
    pub target_kind: Option<String>,
    #[serde(rename = "target_id")]
    pub target_id: Option<i64>,
    #[serde(rename = "target_name")]
    pub target_name: Option<String>,
    pub decision: String,
    #[serde(rename = "requested_status")]
    pub requested_status: Option<String>,
    pub justification: Option<String>,
    pub comment: Option<String>,
    pub actor: Option<String>,
    pub origin: Option<String>,
    #[serde(rename = "decided_at")]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub decided_at: Option<OffsetDateTime>,
    #[serde(rename = "expires_at")]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub lapsed: bool,
    #[serde(rename = "last_reviewed_at")]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_reviewed_at: Option<OffsetDateTime>,
    #[serde(rename = "last_reviewed_by")]
    pub last_reviewed_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Register {
    pub entries: Vec<ExceptionEntry>,
    pub granted: usize,
    #[serde(rename = "awaiting_approval")]
    pub awaiting_approval: usize,
    pub lapsed: usize,
    #[serde(rename = "never_reviewed")]
    pub never_reviewed: usize,
    #[serde(rename = "next_cursor")]
    pub next_cursor: Option<String>,
}

#[derive(Clone)]
pub struct ExceptionsRegisterService {
    db: Db,
}

impl ExceptionsRegisterService {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn register(
        &self,
        limit: usize,
        cursor_str: Option<&str>,
        allowed: &Visibility,
    ) -> Result<Register, IssueError> {
        let capped = limit.clamp(1, MAX_ENTRIES);
        let cursor = parse_cursor(cursor_str);

        let mut tx = crate::persistence::read(&self.db).await?;
        let excepted =
            IssueRepository::register_exceptions(&mut tx, allowed, cursor, capped).await.map_err(IssueError::from)?;

        let issue_ids: Vec<i64> = excepted.iter().map(|i| i.id).collect();
        let events = TriageEventRepository::find_for_issues(&mut tx, &issue_ids).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;

        let mut history_by_issue: BTreeMap<i64, Vec<TriageEventRow>> = BTreeMap::new();
        for event in events {
            history_by_issue.entry(event.issue_id).or_default().push(event);
        }

        let repo_ids: BTreeSet<i64> = excepted.iter().filter_map(|i| i.repo_id).collect();
        let container_ids: BTreeSet<i64> = excepted.iter().filter_map(|i| i.container_id).collect();
        let names =
            naming::for_ids(&self.db, &repo_ids, &container_ids).await.map_err(|e| IssueError::Store(e.to_string()))?;

        let now = OffsetDateTime::now_utc();
        let mut entries = Vec::new();
        for issue in &excepted {
            if let Some(entry) =
                build_entry(issue, history_by_issue.get(&issue.id).cloned().unwrap_or_default(), &names, allowed, now)
            {
                entries.push(entry);
            }
        }

        let granted = entries.iter().filter(|e| e.decision == "not_affected" || e.decision == "will_not_fix").count();
        let awaiting_approval = entries.iter().filter(|e| e.decision == "pending_approval").count();
        let lapsed = entries.iter().filter(|e| e.lapsed).count();
        let never_reviewed = entries.iter().filter(|e| e.last_reviewed_at.is_none()).count();
        let next_cursor = format_next_cursor(&excepted, capped);

        Ok(Register { entries, granted, awaiting_approval, lapsed, never_reviewed, next_cursor })
    }
}

fn parse_cursor(raw: Option<&str>) -> Option<(OffsetDateTime, i64)> {
    let raw = raw?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (milli_str, id_str) = trimmed.split_once(':')?;
    let millis = milli_str.parse::<i64>().ok()?;
    let id = id_str.parse::<i64>().ok()?;
    let nanos = i128::from(millis).checked_mul(1_000_000)?;
    let dt = OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
    Some((dt, id))
}

fn format_next_cursor(read: &[IssueRow], limit: usize) -> Option<String> {
    if read.len() < limit {
        return None;
    }
    let last = read.last()?;
    let triaged_at = last.triaged_at?;
    let millis = triaged_at.unix_timestamp().checked_mul(1_000)?.checked_add(i64::from(triaged_at.millisecond()))?;
    Some(format!("{millis}:{}", last.id))
}

fn build_entry(
    issue: &IssueRow,
    history: Vec<TriageEventRow>,
    names: &naming::Names,
    allowed: &Visibility,
    now: OffsetDateTime,
) -> Option<ExceptionEntry> {
    let target = match (issue.repo_id, issue.container_id) {
        (Some(r), _) => Some(ScanTarget::Repository(r)),
        (None, Some(c)) => Some(ScanTarget::Container(c)),
        (None, None) => None,
    };
    if let Some(t) = &target {
        if !allowed.permits(*t) {
            return None;
        }
    } else if matches!(allowed, Visibility::Only(_)) {
        return None;
    }

    let mut granted: Option<TriageEventRow> = None;
    let mut reviewed: Option<TriageEventRow> = None;
    for event in history {
        if event.origin == REVIEW_ORIGIN {
            reviewed = Some(event);
        } else if event.origin == REOPEN_ORIGIN {
            continue;
        } else if issue.triage_status == event.to_status {
            granted = Some(event);
        }
    }

    let lapsed = issue.triage_expires_at.map(|exp| exp < now).unwrap_or(false);
    let target_kind = match target {
        Some(ScanTarget::Repository(_)) => Some("REPOSITORY".to_string()),
        Some(ScanTarget::Container(_)) => Some("CONTAINER".to_string()),
        None => None,
    };
    let target_id = match target {
        Some(ScanTarget::Repository(id)) | Some(ScanTarget::Container(id)) => Some(id),
        None => None,
    };
    let target_name = if target.is_some() { Some(names.of(issue.repo_id, issue.container_id)) } else { None };

    Some(ExceptionEntry {
        issue_id: issue.id,
        identifier: issue.identifier.clone(),
        severity: issue.severity.clone(),
        target_kind,
        target_id,
        target_name,
        decision: issue.triage_status.clone(),
        requested_status: issue.triage_requested_status.clone(),
        justification: issue.triage_justification.clone(),
        comment: issue.triage_comment.clone(),
        actor: issue.triaged_by.clone(),
        origin: granted.as_ref().map(|g| g.origin.clone()),
        decided_at: issue.triaged_at,
        expires_at: issue.triage_expires_at,
        lapsed,
        last_reviewed_at: reviewed.as_ref().map(|r| r.occurred_at),
        last_reviewed_by: reviewed.as_ref().and_then(|r| r.actor.clone()),
    })
}

#[derive(Clone)]
pub struct ExceptionReviewService {
    db: Db,
    triage: IssueTriageService,
    register: ExceptionsRegisterService,
}

impl ExceptionReviewService {
    pub fn new(db: Db, triage: IssueTriageService, register: ExceptionsRegisterService) -> Self {
        Self { db, triage, register }
    }

    pub async fn review(
        &self,
        issue_id: i64,
        outcome: Option<ReviewOutcome>,
        comment: Option<&str>,
        reviewer: Option<(&str, Role)>,
        new_expiry: Option<OffsetDateTime>,
        allowed: &Visibility,
    ) -> Result<Register, IssueError> {
        let Some((username, role)) = reviewer else {
            return Err(IssueError::Forbidden("Caller is not authenticated".to_string()));
        };
        if role.governs_platform() {
            return Err(IssueError::Forbidden(
                "Reviewing an exception is a triage decision, and the platform governor takes none: it decides the rules the others act under.".to_string(),
            ));
        }
        if !role.can_approve_triage() {
            return Err(IssueError::Forbidden(
                "Reviewing an exception is a triage decision, which this role may not approve.".to_string(),
            ));
        }

        let mut tx = crate::persistence::read(&self.db).await?;
        let issue = IssueRepository::find_by_id(&mut tx, issue_id)
            .await
            .map_err(IssueError::from)?
            .ok_or_else(|| IssueError::NotFound("Issue not found.".to_owned()))?;
        crate::persistence::commit(tx).await?;

        let target = match (issue.repo_id, issue.container_id) {
            (Some(r), _) => ScanTarget::Repository(r),
            (None, Some(c)) => ScanTarget::Container(c),
            (None, None) => return Err(IssueError::NotFound("Issue not found.".to_owned())),
        };
        if !allowed.permits(target) {
            return Err(IssueError::NotFound("Issue not found.".to_owned()));
        }

        // After the role and the issue's visibility, as Java's `IssueTriageService.review` asks it first of what it reads.
        let Some(outcome) = outcome else {
            return Err(IssueError::InvalidInput(
                "A review needs an outcome: CONFIRMED, EXTENDED, REVOKED.".to_owned(),
            ));
        };
        self.triage
            .review_now(issue_id, outcome, comment.map(str::to_owned), Some(username.to_owned()), new_expiry)
            .await?;
        self.register.register(REGISTER_AFTER_REVIEW, None, allowed).await
    }
}

opaque_debug!(ExceptionsRegisterService, ExceptionReviewService);
