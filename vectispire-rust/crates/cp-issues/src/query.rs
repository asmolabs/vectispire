//! `IssueQueryService`: reading pages and details of the backlog.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use time::{Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time};
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_targets::{Targets, naming};
use vectispire_domain::{FindingType, Severity, bounded_text};

use crate::error::IssueError;
use crate::persistence::{IssueFilters, Lifetime};
use crate::persistence::{IssueRepository, IssueRow, TriageEventRepository};
use crate::sla::SlaService;
use crate::triage::TriageStatus;
use crate::views::{BacklogEntry, IssueDetail, IssuePage, Sighting};

pub const MAX_PAGE_SIZE: usize = 500;
pub const MAX_IDENTIFIER_LENGTH: usize = 255;
pub const MAX_SIGHTINGS: usize = 100;
pub const ANY_OWASP_CATEGORY: &str = "ANY";

#[derive(Debug, Clone, Default)]
pub struct BacklogQuery {
    pub state: Option<String>,
    pub severity: Option<String>,
    pub type_: Option<String>,
    pub triage_status: Option<String>,
    pub repository_id: Option<i64>,
    pub container_id: Option<i64>,
    pub project_id: Option<i64>,
    pub solution_id: Option<i64>,
    pub only_direct: bool,
    pub only_kev: bool,
    pub overdue: bool,
    pub unsettled: bool,
    pub search: Option<String>,
    pub identifier: Option<String>,
    pub limit: usize,
    pub offset: usize,
    pub owasp_category: Option<String>,
    pub open_at: Option<String>,
    pub first_seen_from: Option<String>,
    pub first_seen_to: Option<String>,
    pub resolved_from: Option<String>,
    pub resolved_to: Option<String>,
    pub reopened_from: Option<String>,
    pub reopened_to: Option<String>,
}

#[derive(Clone)]
pub struct IssueQueryService {
    db: Db,
    targets: Arc<Targets>,
    scanning: ScanCatalog,
    sla: SlaService,
}

impl IssueQueryService {
    pub const MAX_PAGE_SIZE: usize = MAX_PAGE_SIZE;
    pub const MAX_IDENTIFIER_LENGTH: usize = MAX_IDENTIFIER_LENGTH;

    pub fn new(db: Db, targets: Arc<Targets>, scanning: ScanCatalog, sla: SlaService) -> Self {
        Self { db, targets, scanning, sla }
    }

    pub async fn page(&self, query: BacklogQuery, allowed: &Visibility) -> Result<IssuePage, IssueError> {
        let size = query.limit.clamp(1, MAX_PAGE_SIZE);
        let from = query.offset;

        let filters = self.filters_of(&query, allowed).await?;
        let mut tx = crate::persistence::read(&self.db).await?;
        let (rows, total) =
            IssueRepository::find_page(&mut tx, &filters, from, size).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;

        let items = self.named(&rows).await?;
        Ok(IssuePage {
            items,
            total,
            limit: i32::try_from(size).unwrap_or(i32::MAX),
            offset: i32::try_from(from).unwrap_or(i32::MAX),
        })
    }

    pub async fn count(&self, query: BacklogQuery, allowed: &Visibility) -> Result<i64, IssueError> {
        let filters = self.filters_of(&query, allowed).await?;
        let mut tx = crate::persistence::read(&self.db).await?;
        let total = IssueRepository::count(&mut tx, &filters).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(total)
    }

    pub async fn detail(&self, id: i64, allowed: &Visibility) -> Result<IssueDetail, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let issue = IssueRepository::find_by_id(&mut tx, id)
            .await
            .map_err(IssueError::from)?
            .ok_or_else(|| IssueError::NotFound(format!("Issue {id} not found.")))?;

        let target = match (issue.repo_id, issue.container_id) {
            (Some(r), _) => ScanTarget::Repository(r),
            (None, Some(c)) => ScanTarget::Container(c),
            (None, None) => return Err(IssueError::NotFound(format!("Issue {id} not found."))),
        };
        if !allowed.permits(target) {
            return Err(IssueError::NotFound(format!("Issue {id} not found.")));
        }

        let events = TriageEventRepository::find_for_issues(&mut tx, &[id]).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;

        let sightings_raw =
            self.scanning.sightings(id, MAX_SIGHTINGS).await.map_err(|e| IssueError::Store(e.to_string()))?;
        let sightings = sightings_raw
            .into_iter()
            .map(|s| Sighting {
                scan_id: Some(s.scan.id),
                status: s.scan.status,
                branch: Some(s.scan.branch),
                version: s.scan.version,
                scanned_at: Some(s.scan.created_at),
                severity: s.finding.severity.unwrap_or_else(|| "unknown".to_string()),
            })
            .collect();

        let decisions = events.iter().map(|e| e.to_view()).collect();

        let all_names = naming::all(&self.db).await.map_err(|e| IssueError::Store(e.to_string()))?;
        let target_kind = if issue.repo_id.is_some() { "repository".to_string() } else { "container".to_string() };
        let target_name = all_names.of(issue.repo_id, issue.container_id);

        Ok(IssueDetail { issue: issue.to_view(), target_kind, target_name, sightings, decisions })
    }

    async fn named(&self, rows: &[IssueRow]) -> Result<Vec<BacklogEntry>, IssueError> {
        let repo_ids: BTreeSet<i64> = rows.iter().filter_map(|r| r.repo_id).collect();
        let container_ids: BTreeSet<i64> = rows.iter().filter_map(|r| r.container_id).collect();

        let names =
            naming::for_ids(&self.db, &repo_ids, &container_ids).await.map_err(|e| IssueError::Store(e.to_string()))?;
        let policy = self.sla.policy().await?;
        let now = OffsetDateTime::now_utc();

        let entries = rows
            .iter()
            .map(|row| {
                let settled = TriageStatus::from_wire_name(&row.triage_status).is_some_and(|s| s.is_settled());
                let assessment = policy.assess(
                    Severity::of(Some(row.severity.as_str())),
                    row.first_seen_at,
                    row.state == "open",
                    settled,
                    now,
                );
                BacklogEntry {
                    issue: row.to_view(),
                    target_kind: Some(if row.container_id.is_some() { "container" } else { "repository" }.to_owned()),
                    target_name: names.of(row.repo_id, row.container_id),
                    sla_due_at: assessment.as_ref().map(|a| a.due_at),
                    sla_state: assessment.as_ref().map(|a| a.state.wire_name().to_string()),
                    sla_days: assessment.as_ref().map(|a| a.days),
                }
            })
            .collect();

        Ok(entries)
    }

    async fn filters_of(&self, query: &BacklogQuery, allowed: &Visibility) -> Result<IssueFilters, IssueError> {
        let lifetime = lifetime(query)?;
        let dates_asked = lifetime.is_some();

        let state_val = state(query.state.as_deref(), dates_asked)?;
        let severity_val = severity(query.severity.as_deref())?;
        let type_val = finding_type(query.type_.as_deref())?;
        let identifier_val = identifier(query.identifier.as_deref())?;
        let search_val = bounded_text::optional(query.search.as_deref(), bounded_text::SEARCH_MAX, "search")
            .map_err(|e| IssueError::InvalidInput(e.0))?;
        let owasp_val = owasp_category(query.owasp_category.as_deref())?;

        let overdue_thresholds =
            if query.overdue { self.sla.overdue_thresholds(OffsetDateTime::now_utc()).await? } else { BTreeMap::new() };

        let mut filters = IssueFilters {
            state: state_val,
            severity: severity_val,
            type_: type_val,
            triage_status: query.triage_status.clone(),
            repo_id: query.repository_id,
            container_id: query.container_id,
            only_direct: query.only_direct,
            only_kev: query.only_kev,
            search: search_val,
            exclude_settled: query.overdue || query.unsettled,
            overdue_before: overdue_thresholds,
            visibility: allowed.clone(),
            touching_since: None,
            cve_only: false,
            targets_within: None,
            owasp_category: owasp_val,
            lifetime,
            identifier: identifier_val,
        };

        if let Some(project_id) = query.project_id {
            let members = self.targets.members(project_id).await.map_err(|e| IssueError::Store(e.to_string()))?;
            let targets = members.map(|m| m.targets()).unwrap_or_default();
            filters = filters.within(targets);
        }

        if let Some(solution_id) = query.solution_id {
            let targets =
                self.targets.targets_of_solution(solution_id).await.map_err(|e| IssueError::Store(e.to_string()))?;
            filters = filters.within(targets);
        }

        Ok(filters)
    }
}

fn state(raw: Option<&str>, dates_asked: bool) -> Result<Option<String>, IssueError> {
    let Some(raw) = raw else {
        return Ok(if dates_asked { None } else { Some("open".to_string()) });
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(if dates_asked { None } else { Some("open".to_string()) });
    }
    let lower = trimmed.to_lowercase();
    if lower == "all" {
        return Ok(None);
    }
    if lower == "open" || lower == "resolved" {
        return Ok(Some(lower));
    }
    Err(IssueError::InvalidInput(format!("Unknown state \"{trimmed}\". Expected open, resolved or all.")))
}

fn severity(raw: Option<&str>) -> Result<Option<String>, IssueError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let lower = trimmed.to_lowercase();
    for sev in
        &[Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Negligible, Severity::Unknown]
    {
        if lower == sev.wire_name() {
            return Ok(Some(lower));
        }
    }
    Err(IssueError::InvalidInput(format!(
        "Unknown severity \"{trimmed}\". Expected one of: critical, high, medium, low, negligible, unknown."
    )))
}

fn finding_type(raw: Option<&str>) -> Result<Option<String>, IssueError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let lower = trimmed.to_lowercase();
    for ft in &FindingType::ALL {
        if lower == ft.wire_name() {
            return Ok(Some(lower));
        }
    }
    Err(IssueError::InvalidInput(format!(
        "Unknown finding type \"{trimmed}\". Expected one of: vulnerability, secret, iac, sast, quality, eol, license."
    )))
}

fn owasp_category(raw: Option<&str>) -> Result<Option<String>, IssueError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let upper = trimmed.to_uppercase();
    if upper == ANY_OWASP_CATEGORY {
        return Ok(Some("any".to_string()));
    }
    let valid_categories = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"];
    if valid_categories.contains(&upper.as_str()) {
        return Ok(Some(upper));
    }
    Err(IssueError::InvalidInput(format!(
        "Unknown OWASP category \"{trimmed}\". Expected one of: {}, or any.",
        valid_categories.join(", ")
    )))
}

fn identifier(raw: Option<&str>) -> Result<Option<String>, IssueError> {
    bounded_text::optional(raw, MAX_IDENTIFIER_LENGTH, "identifier").map_err(|e| IssueError::InvalidInput(e.0))
}

fn lifetime(query: &BacklogQuery) -> Result<Option<Lifetime>, IssueError> {
    let open_at = next_midnight("open_at", query.open_at.as_deref())?;
    let first_seen_from = midnight("first_seen_from", query.first_seen_from.as_deref())?;
    let first_seen_before = next_midnight("first_seen_to", query.first_seen_to.as_deref())?;
    let resolved_from = midnight("resolved_from", query.resolved_from.as_deref())?;
    let resolved_before = next_midnight("resolved_to", query.resolved_to.as_deref())?;
    let reopened_from = midnight("reopened_from", query.reopened_from.as_deref())?;
    let reopened_before = next_midnight("reopened_to", query.reopened_to.as_deref())?;

    require_ordered("first_seen", first_seen_from, first_seen_before)?;
    require_ordered("resolved", resolved_from, resolved_before)?;
    require_ordered("reopened", reopened_from, reopened_before)?;

    let lt = Lifetime {
        open_at,
        first_seen_from,
        first_seen_before,
        resolved_from,
        resolved_before,
        reopened_from,
        reopened_before,
    };
    Ok(if lt.asks_anything() { Some(lt) } else { None })
}

fn require_ordered(name: &str, from: Option<OffsetDateTime>, before: Option<OffsetDateTime>) -> Result<(), IssueError> {
    if let (Some(f), Some(b)) = (from, before)
        && f >= b
    {
        return Err(IssueError::InvalidInput(format!("{name}_to comes before {name}_from.")));
    }
    Ok(())
}

fn midnight(name: &str, raw: Option<&str>) -> Result<Option<OffsetDateTime>, IssueError> {
    let Some(d) = parse_day(name, raw)? else {
        return Ok(None);
    };
    let pdt = PrimitiveDateTime::new(d, Time::MIDNIGHT);
    Ok(Some(pdt.assume_utc()))
}

fn next_midnight(name: &str, raw: Option<&str>) -> Result<Option<OffsetDateTime>, IssueError> {
    let Some(d) = parse_day(name, raw)? else {
        return Ok(None);
    };
    let next = d
        .checked_add(Duration::days(1))
        .ok_or_else(|| IssueError::InvalidInput(format!("{name} must be a date between 1970 and 9998.")))?;
    let pdt = PrimitiveDateTime::new(next, Time::MIDNIGHT);
    Ok(Some(pdt.assume_utc()))
}

fn parse_day(name: &str, raw: Option<&str>) -> Result<Option<Date>, IssueError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let mut split = trimmed.split('-');
    let (Some(y_str), Some(m_str), Some(d_str), None) = (split.next(), split.next(), split.next(), split.next()) else {
        return Err(IssueError::InvalidInput(format!("{name} must be an ISO date, YYYY-MM-DD: \"{trimmed}\".")));
    };
    let (Ok(y), Ok(m), Ok(d)) = (y_str.parse::<i32>(), m_str.parse::<u8>(), d_str.parse::<u8>()) else {
        return Err(IssueError::InvalidInput(format!("{name} must be an ISO date, YYYY-MM-DD: \"{trimmed}\".")));
    };
    if !(1970..=9998).contains(&y) {
        return Err(IssueError::InvalidInput(format!("{name} must be a date between 1970 and 9998.")));
    }
    let Ok(month) = Month::try_from(m) else {
        return Err(IssueError::InvalidInput(format!("{name} must be an ISO date, YYYY-MM-DD: \"{trimmed}\".")));
    };
    let Ok(date) = Date::from_calendar_date(y, month, d) else {
        return Err(IssueError::InvalidInput(format!("{name} must be an ISO date, YYYY-MM-DD: \"{trimmed}\".")));
    };
    Ok(Some(date))
}

opaque_debug!(IssueQueryService);
