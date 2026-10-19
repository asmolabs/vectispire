//! Issue views and wire transfer models.

use crate::persistence::{IssueRow, TriageEventRow};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

fn default_reachability() -> String {
    "UNKNOWN".to_owned()
}

/// An issue crossing the API boundary — matches OpenAPI schema `IssueView`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssueView {
    pub id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub fingerprint: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub identifier: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub purl: Option<String>,
    pub file_path: Option<String>,
    pub owasp_category: Option<String>,
    pub source: String,
    pub tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
    pub import_source: Option<String>,
    pub severity: String,
    pub epss_score: Option<f64>,
    #[serde(rename = "isKev")]
    pub is_kev: bool,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub fix_state: Option<String>,
    pub fix_versions: Option<String>,
    pub link: Option<String>,
    pub description: Option<String>,
    pub state: String,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub resolved_at: Option<OffsetDateTime>,
    pub resolution_seconds: Option<i64>,
    pub first_seen_scan_id: Option<i64>,
    pub last_seen_scan_id: Option<i64>,
    pub times_seen: i32,
    pub triage_status: String,
    pub triage_justification: Option<String>,
    pub triage_comment: Option<String>,
    pub triaged_by: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub triaged_at: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub triage_expires_at: Option<OffsetDateTime>,
    pub triage_requested_status: Option<String>,
    #[serde(rename = "isDirectDependency")]
    pub is_direct_dependency: Option<bool>,
    pub line: Option<i32>,
    pub ticket_ref: Option<String>,
    pub ticket_attached_by: Option<String>,
    pub ticket_url: Option<String>,
    #[serde(default = "default_reachability")]
    pub reachability: String,
    pub reachable_symbols: Option<String>,
}

/// An issue with target names and SLA tracking — matches OpenAPI schema `BacklogEntry`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BacklogEntry {
    #[serde(flatten)]
    pub issue: IssueView,
    pub target_kind: Option<String>,
    pub target_name: String,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub sla_due_at: Option<OffsetDateTime>,
    pub sla_state: Option<String>,
    pub sla_days: Option<i64>,
}

/// Page of backlog entries — matches OpenAPI schema `IssuePage`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuePage {
    pub items: Vec<BacklogEntry>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

/// Detailed view of a single issue including sightings and triage history — matches OpenAPI schema `IssueDetail`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssueDetail {
    #[serde(flatten)]
    pub issue: IssueView,
    pub target_kind: String,
    pub target_name: String,
    pub sightings: Vec<Sighting>,
    pub decisions: Vec<DecisionView>,
}

/// One sighting of an issue on a scan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Sighting {
    pub scan_id: Option<i64>,
    pub status: String,
    pub branch: Option<String>,
    pub version: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub scanned_at: Option<OffsetDateTime>,
    pub severity: String,
}

/// One triage transition on an issue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DecisionView {
    pub from_status: String,
    pub to_status: String,
    pub justification: Option<String>,
    pub comment: Option<String>,
    pub actor: Option<String>,
    pub origin: String,
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub scan_id: Option<i64>,
    pub version: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub previous_resolved_at: Option<OffsetDateTime>,
}

// The conversions live here, not beside the rows: a row is the layer below and names nothing above it.
impl IssueRow {
    pub fn to_view(&self) -> IssueView {
        IssueView {
            id: self.id,
            repo_id: self.repo_id,
            container_id: self.container_id,
            fingerprint: self.fingerprint.clone(),
            type_: self.type_.clone(),
            identifier: self.identifier.clone(),
            package_name: self.package_name.clone(),
            package_version: self.package_version.clone(),
            purl: self.purl.clone(),
            file_path: self.file_path.clone(),
            owasp_category: self.owasp_category.clone(),
            source: self.source.clone(),
            tool: self.tool.clone(),
            tool_name: self.tool_name.clone(),
            tool_version: self.tool_version.clone(),
            import_source: self.import_source.clone(),
            severity: self.severity.clone(),
            epss_score: self.epss_score,
            is_kev: self.is_kev,
            cvss_score: self.cvss_score,
            cvss_vector: self.cvss_vector.clone(),
            fix_state: self.fix_state.clone(),
            fix_versions: self.fix_versions.clone(),
            link: self.link.clone(),
            description: self.description.clone(),
            state: self.state.clone(),
            first_seen_at: self.first_seen_at,
            last_seen_at: self.last_seen_at,
            resolved_at: self.resolved_at,
            resolution_seconds: self.resolution_seconds,
            first_seen_scan_id: self.first_seen_scan_id,
            last_seen_scan_id: self.last_seen_scan_id,
            times_seen: self.times_seen,
            triage_status: self.triage_status.clone(),
            triage_justification: self.triage_justification.clone(),
            triage_comment: self.triage_comment.clone(),
            triaged_by: self.triaged_by.clone(),
            triaged_at: self.triaged_at,
            triage_expires_at: self.triage_expires_at,
            triage_requested_status: self.triage_requested_status.clone(),
            is_direct_dependency: self.is_direct_dependency,
            line: self.line,
            ticket_ref: self.ticket_ref.clone(),
            ticket_attached_by: self.ticket_attached_by.clone(),
            ticket_url: self.ticket_url.clone(),
            reachability: self.reachability.clone(),
            reachable_symbols: self.reachable_symbols.clone(),
        }
    }
}

impl TriageEventRow {
    pub fn to_view(&self) -> DecisionView {
        DecisionView {
            from_status: self.from_status.clone(),
            to_status: self.to_status.clone(),
            justification: self.justification.clone(),
            comment: self.comment.clone(),
            actor: self.actor.clone(),
            origin: self.origin.clone(),
            occurred_at: self.occurred_at,
            expires_at: self.expires_at,
            scan_id: self.scan_id,
            version: None,
            previous_resolved_at: self.previous_resolved_at,
        }
    }
}
