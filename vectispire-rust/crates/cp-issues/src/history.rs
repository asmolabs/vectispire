//! `HistoryQueryService`: repositories' detection-and-triage history and dossier exports.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use time::OffsetDateTime;
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_targets::Targets;
use vectispire_domain::repository_url;

use crate::error::IssueError;
use crate::persistence::{IssueRepository, IssueRow, TriageEventRepository, TriageEventRow};
use crate::views::DecisionView;

pub const MAX_SCANS: usize = 200;
pub const ISSUE_BATCH: usize = 1_000;
pub const MAX_FINDINGS: usize = 500;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriageHistoryRepository {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub branch: String,
    pub version: Option<String>,
    #[serde(rename = "projectType")]
    pub project_type: Option<String>,
    #[serde(rename = "scanCount")]
    pub scan_count: usize,
    #[serde(rename = "lastScanAt")]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_scan_at: Option<OffsetDateTime>,
    #[serde(rename = "openIssues")]
    pub open_issues: i64,
    pub decisions: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriageHistoryScan {
    pub id: i64,
    pub status: String,
    pub branch: String,
    pub version: Option<String>,
    #[serde(rename = "projectType")]
    pub project_type: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(rename = "durationMs")]
    pub duration_ms: Option<i64>,
    #[serde(rename = "findingsCount")]
    pub findings_count: i32,
    #[serde(rename = "newIssuesCount")]
    pub new_issues_count: i32,
    #[serde(rename = "resolvedIssuesCount")]
    pub resolved_issues_count: i32,
    pub error: Option<String>,
    pub issues: Vec<ObservedIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedIssue {
    pub id: i64,
    #[serde(rename = "type")]
    pub type_: String,
    pub identifier: String,
    pub severity: String,
    #[serde(rename = "packageName")]
    pub package_name: Option<String>,
    #[serde(rename = "packageVersion")]
    pub package_version: Option<String>,
    #[serde(rename = "filePath")]
    pub file_path: Option<String>,
    pub state: String,
    #[serde(rename = "triageStatus")]
    pub triage_status: String,
    #[serde(rename = "firstSeenAt")]
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen_at: OffsetDateTime,
    #[serde(rename = "resolvedAt")]
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub resolved_at: Option<OffsetDateTime>,
    pub decisions: Vec<DecisionView>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dossier {
    pub repository: TriageHistoryRepository,
    pub scans: Vec<TriageHistoryScan>,
    #[serde(rename = "generatedAt")]
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
}

#[derive(Clone)]
pub struct HistoryQueryService {
    db: Db,
    targets: Arc<Targets>,
    scanning: ScanCatalog,
}

impl HistoryQueryService {
    pub fn new(db: Db, targets: Arc<Targets>, scanning: ScanCatalog) -> Self {
        Self { db, targets, scanning }
    }

    pub async fn repositories(
        &self,
        allowed: &Visibility,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<TriageHistoryRepository>, IssueError> {
        let last_scan_at =
            self.scanning.last_scan_at_per_repository().await.map_err(|e| IssueError::Store(e.to_string()))?;
        let all_repos = self.targets.catalog_repositories().await.map_err(|e| IssueError::Store(e.to_string()))?;

        let mut visible: Vec<_> =
            all_repos.into_iter().filter(|r| allowed.permits(ScanTarget::Repository(r.id))).collect();

        visible.sort_by(|a, b| {
            let a_time = last_scan_at.get(&a.id);
            let b_time = last_scan_at.get(&b.id);
            match (a_time, b_time) {
                (Some(at), Some(bt)) => bt.cmp(at).then(a.id.cmp(&b.id)),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.id.cmp(&b.id),
            }
        });

        let from = offset.unwrap_or(0);
        let sliced: Vec<_> = if let Some(l) = limit {
            visible.iter().skip(from).take(l).cloned().collect()
        } else {
            visible.iter().skip(from).cloned().collect()
        };

        let mut rows = Vec::with_capacity(sliced.len());
        for repo in sliced {
            rows.push(self.row_of(repo.id, repo.name.as_deref(), &repo.url, &repo.branch).await?);
        }

        Ok(rows)
    }

    pub async fn dossier(&self, id: i64, limit: usize, allowed: &Visibility) -> Result<Dossier, IssueError> {
        let repo = self.visible_repository(id, allowed).await?;
        let repository = self.row_of(repo.id, repo.name.as_deref(), &repo.url, &repo.branch).await?;
        let scans = self.scan_rows(id, limit.clamp(1, MAX_SCANS)).await?;
        let generated_at = OffsetDateTime::now_utc();
        Ok(Dossier { repository, scans, generated_at })
    }

    pub async fn csv(&self, id: i64, allowed: &Visibility) -> Result<Vec<u8>, IssueError> {
        let repo = self.visible_repository(id, allowed).await?;
        let repository = self.row_of(repo.id, repo.name.as_deref(), &repo.url, &repo.branch).await?;
        let scans = self.scan_rows(id, MAX_SCANS).await?;
        let rendered = TriageHistoryCsv::render(&repository, &scans);
        Ok(rendered.into_bytes())
    }

    async fn visible_repository(
        &self,
        id: i64,
        allowed: &Visibility,
    ) -> Result<vectispire_cp_targets::views::RepositoryView, IssueError> {
        if !allowed.permits(ScanTarget::Repository(id)) {
            return Err(IssueError::NotFound(format!("Repository {id} not found.")));
        }
        let repo = self
            .targets
            .catalog_repository(id)
            .await
            .map_err(|e| IssueError::Store(e.to_string()))?
            .ok_or_else(|| IssueError::NotFound(format!("Repository {id} not found.")))?;
        Ok(repo)
    }

    async fn row_of(
        &self,
        repo_id: i64,
        raw_name: Option<&str>,
        url: &str,
        branch: &str,
    ) -> Result<TriageHistoryRepository, IssueError> {
        let history =
            self.scanning.history(repo_id, None, MAX_SCANS).await.map_err(|e| IssueError::Store(e.to_string()))?;
        let version =
            history.iter().filter_map(|s| s.version.as_deref()).find(|v| !v.trim().is_empty()).map(str::to_string);
        let project_type =
            history.iter().filter_map(|s| s.project_type.as_deref()).find(|p| !p.trim().is_empty()).map(str::to_string);
        let last_scan_at = history.iter().map(|s| s.created_at).max();

        let redacted_url = repository_url::redact(url);
        let display_name = match raw_name {
            Some(n) if !n.trim().is_empty() => n.to_string(),
            _ => redacted_url.clone(),
        };

        let mut tx = crate::persistence::read(&self.db).await?;
        let open_issues =
            IssueRepository::count_by_state_and_repository(&mut tx, "open", repo_id).await.map_err(IssueError::from)?;
        let decisions =
            TriageEventRepository::count_for_repository(&mut tx, repo_id, "reopen").await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;

        Ok(TriageHistoryRepository {
            id: repo_id,
            name: display_name,
            url: redacted_url,
            branch: branch.to_string(),
            version,
            project_type,
            scan_count: history.len(),
            last_scan_at,
            open_issues,
            decisions,
        })
    }

    async fn scan_rows(&self, repo_id: i64, limit: usize) -> Result<Vec<TriageHistoryScan>, IssueError> {
        let history =
            self.scanning.history(repo_id, None, limit).await.map_err(|e| IssueError::Store(e.to_string()))?;
        let scan_ids: Vec<i64> = history.iter().map(|s| s.id).collect();

        let findings =
            self.scanning.findings_of_scans(&scan_ids).await.map_err(|e| IssueError::Store(e.to_string()))?;
        let mut findings_by_scan: BTreeMap<i64, Vec<vectispire_cp_scanning::views::ScanFindingView>> = BTreeMap::new();
        for f in findings {
            findings_by_scan.entry(f.scan_id).or_default().push(f);
        }

        let issue_ids: Vec<i64> = findings_by_scan
            .values()
            .flat_map(|fs| fs.iter().filter_map(|f| f.issue_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let mut issues_by_id: BTreeMap<i64, IssueRow> = BTreeMap::new();
        let mut decisions_by_issue: BTreeMap<i64, Vec<TriageEventRow>> = BTreeMap::new();

        let mut tx = crate::persistence::read(&self.db).await?;
        for chunk in issue_ids.chunks(ISSUE_BATCH) {
            let issues = IssueRepository::find_by_ids(&mut tx, chunk).await.map_err(IssueError::from)?;
            for issue in issues {
                issues_by_id.insert(issue.id, issue);
            }
            let events = TriageEventRepository::find_for_issues(&mut tx, chunk).await.map_err(IssueError::from)?;
            for event in events {
                decisions_by_issue.entry(event.issue_id).or_default().push(event);
            }
        }
        crate::persistence::commit(tx).await?;

        let mut version_by_scan: BTreeMap<i64, Option<String>> = BTreeMap::new();
        for scan in &history {
            version_by_scan.insert(scan.id, scan.version.clone());
        }

        let mut scan_rows = Vec::with_capacity(history.len());
        for scan in history {
            let mut observed = Vec::new();
            let mut already = HashSet::new();

            if let Some(scan_findings) = findings_by_scan.get(&scan.id) {
                for finding in scan_findings {
                    let Some(issue_id) = finding.issue_id else {
                        continue;
                    };
                    let Some(issue) = issues_by_id.get(&issue_id) else {
                        continue;
                    };
                    if !already.insert(issue.id) || observed.len() >= MAX_FINDINGS {
                        continue;
                    }
                    let issue_events = decisions_by_issue.get(&issue.id).cloned().unwrap_or_default();
                    observed.push(observed_of(issue, issue_events, &version_by_scan));
                }
            }

            scan_rows.push(TriageHistoryScan {
                id: scan.id,
                status: scan.status,
                branch: scan.branch,
                version: scan.version,
                project_type: scan.project_type,
                created_at: scan.created_at,
                duration_ms: scan.duration_ms,
                findings_count: scan.findings_count,
                new_issues_count: scan.new_issues_count,
                resolved_issues_count: scan.resolved_issues_count,
                error: scan.error,
                issues: observed,
            });
        }

        Ok(scan_rows)
    }
}

fn observed_of(
    issue: &IssueRow,
    events: Vec<TriageEventRow>,
    version_by_scan: &BTreeMap<i64, Option<String>>,
) -> ObservedIssue {
    let decisions = events
        .into_iter()
        .map(|event| {
            let version = event.scan_id.and_then(|sid| version_by_scan.get(&sid).cloned().flatten());
            DecisionView {
                from_status: event.from_status,
                to_status: event.to_status,
                justification: event.justification,
                comment: event.comment,
                actor: event.actor,
                origin: event.origin,
                occurred_at: event.occurred_at,
                expires_at: event.expires_at,
                scan_id: event.scan_id,
                version,
                previous_resolved_at: event.previous_resolved_at,
            }
        })
        .collect();

    ObservedIssue {
        id: issue.id,
        type_: issue.type_.clone(),
        identifier: issue.identifier.clone(),
        severity: issue.severity.clone(),
        package_name: issue.package_name.clone(),
        package_version: issue.package_version.clone(),
        file_path: issue.file_path.clone(),
        state: issue.state.clone(),
        triage_status: issue.triage_status.clone(),
        first_seen_at: issue.first_seen_at,
        resolved_at: issue.resolved_at,
        decisions,
    }
}

pub struct TriageHistoryCsv;

impl TriageHistoryCsv {
    pub const HEADER: [&'static str; 27] = [
        "repository",
        "repository_url",
        "scan_id",
        "scan_at",
        "scan_status",
        "branch",
        "project_type",
        "version",
        "issue_id",
        "issue_type",
        "identifier",
        "severity",
        "component",
        "location",
        "issue_state",
        "current_triage",
        "first_seen_at",
        "resolved_at",
        "decision_at",
        "decision_from",
        "decision_to",
        "decision_justification",
        "decision_actor",
        "decision_origin",
        "decision_expires_at",
        "decision_comment",
        "decision_previous_resolved_at",
    ];

    pub fn render(repository: &TriageHistoryRepository, scans: &[TriageHistoryScan]) -> String {
        let mut csv = String::new();
        csv.push_str(&Self::HEADER.join(","));
        csv.push('\n');

        for scan in scans {
            for issue in &scan.issues {
                if issue.decisions.is_empty() {
                    csv.push_str(&Self::line(repository, scan, issue, None));
                    csv.push('\n');
                } else {
                    for decision in &issue.decisions {
                        csv.push_str(&Self::line(repository, scan, issue, Some(decision)));
                        csv.push('\n');
                    }
                }
            }
        }
        csv
    }

    fn line(
        repository: &TriageHistoryRepository,
        scan: &TriageHistoryScan,
        issue: &ObservedIssue,
        decision: Option<&DecisionView>,
    ) -> String {
        let scan_id_str = scan.id.to_string();
        let issue_id_str = issue.id.to_string();
        let component_str = Self::component(issue);
        let scan_at_str = Self::stamp(Some(scan.created_at));
        let first_seen_str = Self::stamp(Some(issue.first_seen_at));
        let resolved_str = Self::stamp(issue.resolved_at);

        let dec_at_str = Self::stamp(decision.map(|d| d.occurred_at));
        let dec_expires_str = Self::stamp(decision.and_then(|d| d.expires_at));
        let dec_prev_resolved_str = Self::stamp(decision.and_then(|d| d.previous_resolved_at));

        let cells: [&str; 27] = [
            &repository.name,
            &repository.url,
            &scan_id_str,
            &scan_at_str,
            &scan.status,
            &scan.branch,
            scan.project_type.as_deref().unwrap_or(""),
            scan.version.as_deref().unwrap_or(""),
            &issue_id_str,
            &issue.type_,
            &issue.identifier,
            &issue.severity,
            &component_str,
            issue.file_path.as_deref().unwrap_or(""),
            &issue.state,
            &issue.triage_status,
            &first_seen_str,
            &resolved_str,
            &dec_at_str,
            decision.map(|d| d.from_status.as_str()).unwrap_or(""),
            decision.map(|d| d.to_status.as_str()).unwrap_or(""),
            decision.and_then(|d| d.justification.as_deref()).unwrap_or(""),
            decision.and_then(|d| d.actor.as_deref()).unwrap_or(""),
            decision.map(|d| d.origin.as_str()).unwrap_or(""),
            &dec_expires_str,
            decision.and_then(|d| d.comment.as_deref()).unwrap_or(""),
            &dec_prev_resolved_str,
        ];

        cells.iter().map(|&cell| Self::quote(cell)).collect::<Vec<_>>().join(",")
    }

    fn component(issue: &ObservedIssue) -> String {
        match (&issue.package_name, &issue.package_version) {
            (Some(name), Some(version)) => format!("{name} {version}"),
            (Some(name), None) => name.clone(),
            _ => String::new(),
        }
    }

    fn stamp(instant: Option<OffsetDateTime>) -> String {
        instant.map(|i| i.to_string()).unwrap_or_default()
    }

    fn neutralize(value: &str) -> String {
        let first = value.chars().next();
        if let Some('=' | '+' | '-' | '@' | '\t' | '\r') = first { format!("'{value}") } else { value.to_string() }
    }

    fn quote(value: &str) -> String {
        let safe = Self::neutralize(value);
        format!("\"{}\"", safe.replace('\"', "\"\""))
    }
}

opaque_debug!(HistoryQueryService, TriageHistoryCsv);
