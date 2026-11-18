//! One repository's OWASP report as the route reads it — Java's `OwaspReportService.latest`, `OwaspReportLinks`,
//! `AiReviewResultView`, `AiReviewStatus` and `EvidenceIdentifiers`.
//!
//! **Read only, here.** Writing a report asks a model, and the client that asks one is the `ai` module's (wave 2):
//! the request (`POST`), the after-scan writer and the PDF wait for it. What a reader is served — the latest row read
//! as of now, the backlog's figures beside it, the links from the identifiers the model was shown — needs none of it.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;
use time::OffsetDateTime;
use vectispire_cp_access::rows::require_visible_repository;
use vectispire_cp_db::{Db, Visibility};
use vectispire_cp_issues::queries::{IssueCatalog, IssueFilters};
use vectispire_cp_issues::{BacklogQuery, IssueQueryService};
use vectispire_cp_targets::{Clock, Targets};
use vectispire_domain::owasp_coverage;

use crate::error::ComplianceError;
use crate::markdown::{self, Block};
use crate::matrix::instant;
use crate::persistence::repository::ReviewRepository;
use crate::persistence::{self, ReviewRow};
use crate::weekly::Stamp;

/// `AiReviewStatus` wire names.
pub const RUNNING: &str = "running";
pub const COMPLETED: &str = "completed";
pub const FAILED: &str = "failed";

/// `AiReviewStatus.ABANDONED`: what a review says once its deadline passed with nobody left to settle it.
pub const ABANDONED: &str = "The control plane stopped before the model answered, and nothing is waiting for this \
                             report any more. Ask for it again.";

const NO_REPORT: &str = "No OWASP report has been produced for this target.";

/// `AiReviewStatus.isAbandoned`: running, and past the deadline by which whoever asked would have settled it.
pub fn is_abandoned(stored: &str, deadline: Option<OffsetDateTime>, now: OffsetDateTime) -> bool {
    stored == RUNNING && deadline.is_some_and(|deadline| deadline < now)
}

/// `AiReviewStatus.effective`: **the status a row is in now**, not the one it was written with — a review running past
/// its deadline reads as failed from that moment, not from the hourly sweep that writes it so.
pub fn effective(stored: &str, deadline: Option<OffsetDateTime>, now: OffsetDateTime) -> &str {
    if is_abandoned(stored, deadline, now) { FAILED } else { stored }
}

/// `EvidenceIdentifiers.read`: the identifiers the model was shown, or none when the column holds nothing readable —
/// **none, not an empty list**, which would say the model was shown nothing identified. Jackson's reading of a
/// `List<String>`: a scalar element is taken as its text, a null element or anything else makes the whole unreadable.
pub fn evidence_identifiers(column: Option<&str>) -> Option<Vec<String>> {
    let column = column.filter(|text| !vectispire_domain::java::is_blank(text))?;
    let serde_json::Value::Array(elements) = serde_json::from_str(column).ok()? else {
        return None;
    };
    elements
        .into_iter()
        .map(|element| match element {
            serde_json::Value::String(text) => Some(text),
            serde_json::Value::Number(number) => Some(number.to_string()),
            serde_json::Value::Bool(flag) => Some(flag.to_string()),
            _ => None,
        })
        .collect()
}

/// Where a cited identifier leads: the issue when exactly one carries it, and how many do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueLink {
    pub issue_id: Option<i64>,
    pub count: i64,
}

/// `OwaspController.Report`, members in the record's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub id: i64,
    pub status: String,
    pub model: String,
    pub content: Option<String>,
    pub blocks: Vec<Block>,
    pub error: Option<String>,
    pub scan_id: i64,
    pub inputs: Option<String>,
    pub created_at: Stamp,
    /// `A01` to `A10` in that order, a zero included.
    pub category_findings: Ordered,
    /// In the order the model was shown them; none when the review recorded no identifiers (before V84).
    pub issue_links: Option<OrderedLinks>,
}

/// A map serialized in the order its entries were put — Java's `LinkedHashMap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ordered(pub Vec<(&'static str, i64)>);

impl Serialize for Ordered {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(key, value)| (*key, *value)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedLinks(pub Vec<(String, IssueLink)>);

impl Serialize for OrderedLinks {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(key, value)| (key, value)))
    }
}

#[derive(Clone)]
pub struct OwaspReportService {
    db: Db,
    targets: Arc<Targets>,
    backlog: Arc<IssueQueryService>,
    issues: Arc<IssueCatalog>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for OwaspReportService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OwaspReportService").finish_non_exhaustive()
    }
}

impl OwaspReportService {
    pub fn new(
        db: Db,
        targets: Arc<Targets>,
        backlog: Arc<IssueQueryService>,
        issues: Arc<IssueCatalog>,
        clock: Arc<dyn Clock>,
    ) -> OwaspReportService {
        OwaspReportService { db, targets, backlog, issues, clock }
    }

    /// `latest`: a hidden or absent repository reads alike, then one never reviewed is a 404 of its own sentence.
    pub async fn latest(&self, repository_id: i64, allowed: &Visibility) -> Result<Report, ComplianceError> {
        let found = self.targets.catalog_repository(repository_id).await.map_err(ComplianceError::unexpected)?;
        require_visible_repository(found, repository_id, allowed)
            .map_err(|refused| ComplianceError::NotFound(refused.message.to_owned()))?;
        let mut tx = persistence::read(&self.db).await?;
        let row = ReviewRepository::latest_for_repository(&mut tx, repository_id).await?;
        persistence::commit(tx).await?;
        let row = row.ok_or_else(|| ComplianceError::NotFound(NO_REPORT.to_owned()))?;
        let shown = evidence_identifiers(row.evidence_identifiers.as_deref());
        let category_findings = self.category_findings(repository_id, allowed).await?;
        let issue_links = self.issue_links(repository_id, shown.as_deref(), allowed).await?;
        Ok(report(row, self.clock.now(), category_findings, issue_links))
    }

    /// `categoryFindings`: **the backlog's own count** for the query the screen's link carries — open, unsettled
    /// triage left out, placed as the grid places — so the figure on a link is the length of the list it opens. Ten
    /// counts rather than one grouped query, which would be a second placement rule.
    async fn category_findings(&self, repository_id: i64, allowed: &Visibility) -> Result<Ordered, ComplianceError> {
        let mut counts = Vec::new();
        for category in owasp_coverage::codes() {
            let query = BacklogQuery {
                repository_id: Some(repository_id),
                unsettled: true,
                limit: 1,
                owasp_category: Some(category.to_owned()),
                ..BacklogQuery::default()
            };
            counts.push((category, self.backlog.count(query, allowed).await.map_err(ComplianceError::unexpected)?));
        }
        Ok(Ordered(counts))
    }

    /// `issueLinks`: **the evidence, never the prose** — only the identifiers the review recorded it showed the model,
    /// each matched by the list's own key against the repository's open issues the caller sees.
    async fn issue_links(
        &self,
        repository_id: i64,
        shown: Option<&[String]>,
        allowed: &Visibility,
    ) -> Result<Option<OrderedLinks>, ComplianceError> {
        let Some(shown) = shown else {
            return Ok(None);
        };
        if shown.is_empty() {
            return Ok(Some(OrderedLinks(Vec::new())));
        }
        let mut filters = IssueFilters::new(allowed.clone());
        filters.repo_id = Some(repository_id);
        let mut carrying: HashMap<String, Vec<i64>> = HashMap::new();
        for issue in self.issues.identified(&filters).await.map_err(ComplianceError::unexpected)? {
            if let Some(key) = IssueFilters::identifier_key(issue.identifier.as_deref()) {
                carrying.entry(key).or_default().push(issue.id);
            }
        }
        let mut links: Vec<(String, IssueLink)> = Vec::new();
        for identifier in shown {
            let Some(ids) = IssueFilters::identifier_key(Some(identifier)).and_then(|key| carrying.get(&key)) else {
                continue;
            };
            let count = i64::try_from(ids.len()).unwrap_or(i64::MAX);
            let link = IssueLink { issue_id: if ids.len() == 1 { ids.first().copied() } else { None }, count };
            // `LinkedHashMap.put`: a repeated identifier keeps its first place and takes the last value, the same one.
            match links.iter_mut().find(|(known, _)| known == identifier) {
                Some(entry) => entry.1 = link,
                None => links.push((identifier.clone(), link)),
            }
        }
        Ok(Some(OrderedLinks(links)))
    }
}

/// `OwaspController.reportOf` over `AiReviewResultView.of`: the status and error as of `now`.
fn report(
    row: ReviewRow,
    now: OffsetDateTime,
    category_findings: Ordered,
    issue_links: Option<OrderedLinks>,
) -> Report {
    let abandoned = is_abandoned(&row.status, row.deadline_at, now);
    Report {
        id: row.id,
        status: if abandoned { FAILED.to_owned() } else { row.status },
        model: row.model,
        blocks: markdown::parse(row.response.as_deref()),
        content: row.response,
        error: if abandoned { Some(ABANDONED.to_owned()) } else { row.error },
        scan_id: row.scan_id,
        inputs: row.inputs,
        created_at: Stamp(instant(row.created_at)),
        category_findings,
        issue_links,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identifiers_read_as_jackson_reads_them() {
        assert_eq!(evidence_identifiers(None), None);
        assert_eq!(evidence_identifiers(Some("  ")), None);
        assert_eq!(evidence_identifiers(Some("null")), None);
        assert_eq!(evidence_identifiers(Some("{}")), None);
        assert_eq!(evidence_identifiers(Some("[\"a\",null]")), None);
        assert_eq!(evidence_identifiers(Some("[]")), Some(vec![]));
        assert_eq!(evidence_identifiers(Some("[\"CVE-1\",2]")), Some(vec!["CVE-1".to_owned(), "2".to_owned()]));
    }
}
