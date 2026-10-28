//! The answers, member for member as Jackson writes the Java records: components in declaration order, `null`
//! written rather than left out, instants in `ISO_INSTANT`'s groups of three digits, identifiers as hyphenated
//! lower-case text, strings escaped as Jackson escapes them (`vectispire_domain::wire`).

use axum::body::Body;
use axum::response::Response;
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_domain::repository_url;

use crate::containers::{self, Listed as ListedContainer};
use crate::credentials::{KeyView, TokenView};
use crate::ports::LatestScan;
use crate::repositories::{Duplicated, Listed as ListedRepository};
use crate::tree::{OpenIssues, ProjectDetail, ProjectNode, SolutionNode, SolutionTree, TargetRef, Unfiled};
use crate::views::{ProjectView, SolutionView};

/// A `200` (or `201`) with the body Jackson would have written.
pub fn ok<T: Serialize + ?Sized>(status: StatusCode, value: &T) -> Response {
    let mut response = Response::new(Body::from(vectispire_domain::wire::to_wire_string(value)));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// A `204`.
pub fn no_content() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    response
}

/// `InstantSerializer` with `ISO_INSTANT`: the fraction in groups of three digits, none when it is zero.
pub fn instant(value: OffsetDateTime) -> String {
    vectispire_cp_audit::iso_instant(value)
}

fn instant_of(value: Option<OffsetDateTime>) -> Option<String> {
    value.map(instant)
}

fn uuid_of(value: Option<Uuid>) -> Option<String> {
    value.map(|id| id.as_hyphenated().to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastScan {
    id: i64,
    status: String,
    created_at: String,
    error: Option<String>,
}

impl LastScan {
    fn of(scan: &LatestScan) -> LastScan {
        LastScan {
            id: scan.id,
            status: scan.status.clone(),
            created_at: instant(scan.created_at),
            error: scan.error.clone(),
        }
    }
}

/// `ScheduleInForce`: the mode, and the minutes it runs every — `null` under a cron expression, manual only, and a
/// default the installation does not set.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleInForce {
    mode: &'static str,
    interval_minutes: Option<i64>,
}

impl ScheduleInForce {
    fn of(in_force: vectispire_domain::schedules::InForce) -> ScheduleInForce {
        ScheduleInForce { mode: in_force.mode.wire_name(), interval_minutes: in_force.interval_minutes }
    }
}

/// `RepositorySummary`: the URL redacted, never as stored.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositorySummary {
    id: i64,
    url: String,
    branch: String,
    name: Option<String>,
    sub_path: Option<String>,
    display_name: String,
    scan_interval_minutes: Option<i32>,
    scan_cron: Option<String>,
    scan_manual_only: bool,
    schedule: ScheduleInForce,
    required_agent_label: Option<String>,
    ssh_key_id: Option<String>,
    https_token_id: Option<String>,
    last_scheduled_scan_at: Option<String>,
    last_scan: Option<LastScan>,
    open_issues: i64,
    tier: String,
    project_id: Option<i64>,
    project_name: Option<String>,
    /// **`null` — sent, not omitted — when unknown**; never `[]` for that: `[]` is a whole census that saw none.
    detected_languages: Option<Vec<String>>,
}

impl RepositorySummary {
    pub fn of(listed: &ListedRepository) -> RepositorySummary {
        let repository = &listed.repository;
        RepositorySummary {
            id: repository.id,
            url: repository_url::redact(&repository.url),
            branch: repository.branch.clone(),
            name: repository.name.clone(),
            sub_path: repository.sub_path.clone(),
            display_name: repository_url::display_name(repository.name.as_deref(), &repository.url),
            scan_interval_minutes: repository.scan_interval_minutes,
            scan_cron: repository.scan_cron.clone(),
            scan_manual_only: repository.scan_manual_only,
            schedule: ScheduleInForce::of(listed.schedule),
            required_agent_label: repository.required_agent_label.clone(),
            ssh_key_id: uuid_of(repository.ssh_key_id),
            https_token_id: uuid_of(repository.https_token_id),
            last_scheduled_scan_at: instant_of(repository.last_scheduled_scan_at),
            last_scan: listed.latest_scan.as_ref().map(LastScan::of),
            open_issues: listed.open_issues,
            tier: repository.tier.clone(),
            project_id: repository.project_id,
            project_name: listed.project_name.clone(),
            // A `BTreeSet` of wire names: `Language`'s declaration order is their alphabetical one.
            detected_languages: listed.detected_languages.as_ref().map(|languages| languages.iter().cloned().collect()),
        }
    }
}

/// `DuplicateTarget`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateTarget {
    repository: String,
    branch: String,
    sub_path: String,
    targets: Vec<RepositorySummary>,
}

impl DuplicateTarget {
    pub fn of(group: &Duplicated) -> DuplicateTarget {
        DuplicateTarget {
            repository: group.identity.repository.clone(),
            branch: group.identity.branch.clone(),
            sub_path: group.identity.sub_path.clone(),
            targets: group.targets.iter().map(RepositorySummary::of).collect(),
        }
    }
}

/// `ContainerSummary`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSummary {
    id: i64,
    registry: Option<String>,
    image_name: String,
    tag: String,
    reference: String,
    display_name: String,
    scan_interval_minutes: Option<i32>,
    scan_cron: Option<String>,
    scan_manual_only: bool,
    schedule: ScheduleInForce,
    required_agent_label: Option<String>,
    last_scheduled_scan_at: Option<String>,
    last_scan: Option<LastScan>,
    open_issues: i64,
    tier: String,
    project_id: Option<i64>,
    project_name: Option<String>,
}

impl ContainerSummary {
    pub fn of(listed: &ListedContainer) -> ContainerSummary {
        let container = &listed.container;
        let reference = containers::reference_of(container);
        ContainerSummary {
            id: container.id,
            registry: container.registry.clone(),
            image_name: container.image_name.clone(),
            tag: container.tag.clone(),
            reference: reference.format(),
            display_name: reference.display_name(),
            scan_interval_minutes: container.scan_interval_minutes,
            scan_cron: container.scan_cron.clone(),
            scan_manual_only: container.scan_manual_only,
            schedule: ScheduleInForce::of(listed.schedule),
            required_agent_label: container.required_agent_label.clone(),
            last_scheduled_scan_at: instant_of(container.last_scheduled_scan_at),
            last_scan: listed.latest_scan.as_ref().map(LastScan::of),
            open_issues: listed.open_issues,
            tier: container.tier.clone(),
            project_id: container.project_id,
            project_name: listed.project_name.clone(),
        }
    }
}

/// `QueuedScan`.
#[derive(Serialize)]
pub struct QueuedScan {
    pub id: i64,
    pub status: String,
}

/// `SolutionView`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Solution {
    id: i64,
    name: String,
    description: Option<String>,
    created_at: String,
}

impl Solution {
    pub fn of(view: &SolutionView) -> Solution {
        Solution {
            id: view.id,
            name: view.name.clone(),
            description: view.description.clone(),
            created_at: instant(view.created_at),
        }
    }
}

/// `ProjectView`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    id: i64,
    solution_id: i64,
    name: String,
    description: Option<String>,
    created_at: String,
}

impl Project {
    pub fn of(view: &ProjectView) -> Project {
        Project {
            id: view.id,
            solution_id: view.solution_id,
            name: view.name.clone(),
            description: view.description.clone(),
            created_at: instant(view.created_at),
        }
    }
}

#[derive(Serialize)]
pub struct Figures {
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    negligible: i64,
    unknown: i64,
    total: i64,
}

impl Figures {
    fn of(open: OpenIssues) -> Figures {
        Figures {
            critical: open.critical,
            high: open.high,
            medium: open.medium,
            low: open.low,
            negligible: open.negligible,
            unknown: open.unknown,
            total: open.total,
        }
    }
}

#[derive(Serialize)]
pub struct Ref {
    id: i64,
    name: String,
}

fn refs(targets: &[TargetRef]) -> Vec<Ref> {
    targets.iter().map(|target| Ref { id: target.id, name: target.name.clone() }).collect()
}

/// `ProjectNode`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    id: i64,
    solution_id: i64,
    name: String,
    description: Option<String>,
    created_at: String,
    partial: bool,
    checklists_visible: bool,
    repository_count: i64,
    open_issues: Figures,
    repositories: Vec<Ref>,
    detected_languages: Vec<String>,
    languages_unknown_for: Vec<i64>,
    container_count: i64,
    containers: Vec<Ref>,
}

impl Node {
    fn of(node: &ProjectNode) -> Node {
        Node {
            id: node.id,
            solution_id: node.solution_id,
            name: node.name.clone(),
            description: node.description.clone(),
            created_at: instant(node.created_at),
            partial: node.partial,
            checklists_visible: node.checklists_visible,
            repository_count: node.repository_count,
            open_issues: Figures::of(node.open_issues),
            repositories: refs(&node.repositories),
            detected_languages: node.detected_languages.clone(),
            languages_unknown_for: node.languages_unknown_for.clone(),
            container_count: node.container_count,
            containers: refs(&node.containers),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SolutionBranch {
    id: i64,
    name: String,
    description: Option<String>,
    created_at: String,
    partial: bool,
    repository_count: i64,
    open_issues: Figures,
    projects: Vec<Node>,
    container_count: i64,
}

impl SolutionBranch {
    fn of(node: &SolutionNode) -> SolutionBranch {
        SolutionBranch {
            id: node.id,
            name: node.name.clone(),
            description: node.description.clone(),
            created_at: instant(node.created_at),
            partial: node.partial,
            repository_count: node.repository_count,
            open_issues: Figures::of(node.open_issues),
            projects: node.projects.iter().map(Node::of).collect(),
            container_count: node.container_count,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnfiledBranch {
    repository_count: i64,
    open_issues: Figures,
    repositories: Vec<Ref>,
    container_count: i64,
    containers: Vec<Ref>,
}

/// `SolutionTree`.
#[derive(Serialize)]
pub struct Tree {
    solutions: Vec<SolutionBranch>,
    unfiled: UnfiledBranch,
}

impl Tree {
    pub fn of(tree: &SolutionTree) -> Tree {
        let Unfiled { repository_count, open_issues, repositories, container_count, containers } = &tree.unfiled;
        Tree {
            solutions: tree.solutions.iter().map(SolutionBranch::of).collect(),
            unfiled: UnfiledBranch {
                repository_count: *repository_count,
                open_issues: Figures::of(*open_issues),
                repositories: refs(repositories),
                container_count: *container_count,
                containers: refs(containers),
            },
        }
    }
}

#[derive(Serialize)]
pub struct SolutionRef {
    id: i64,
    name: Option<String>,
}

/// `ProjectDetail`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Detail {
    id: i64,
    solution_id: i64,
    solution: SolutionRef,
    name: String,
    description: Option<String>,
    created_at: String,
    partial: bool,
    checklists_visible: bool,
    repository_count: i64,
    open_issues: Figures,
    repositories: Vec<Ref>,
    detected_languages: Vec<String>,
    languages_unknown_for: Vec<i64>,
    container_count: i64,
    containers: Vec<Ref>,
}

impl Detail {
    pub fn of(detail: &ProjectDetail) -> Detail {
        let node = Node::of(&detail.node);
        Detail {
            id: node.id,
            solution_id: node.solution_id,
            solution: SolutionRef { id: node.solution_id, name: detail.solution_name.clone() },
            name: node.name,
            description: node.description,
            created_at: node.created_at,
            partial: node.partial,
            checklists_visible: node.checklists_visible,
            repository_count: node.repository_count,
            open_issues: node.open_issues,
            repositories: node.repositories,
            detected_languages: node.detected_languages,
            languages_unknown_for: node.languages_unknown_for,
            container_count: node.container_count,
            containers: node.containers,
        }
    }
}

/// `GitTokenSummary`: never the token.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GitTokenSummary {
    id: String,
    name: String,
    host: String,
    username: Option<String>,
    created_at: String,
    encryption_state: String,
    used_by_repositories: i64,
}

impl GitTokenSummary {
    pub fn of(token: &TokenView) -> GitTokenSummary {
        GitTokenSummary {
            id: token.id.as_hyphenated().to_string(),
            name: token.name.clone(),
            host: token.host.clone(),
            username: token.username.clone(),
            created_at: instant(token.created_at),
            encryption_state: token.encryption_state.clone(),
            used_by_repositories: token.used_by_repositories,
        }
    }
}

/// `SshKeySummary`: the public half only.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeySummary {
    id: String,
    name: String,
    public_key: Option<String>,
    created_at: String,
    encryption_state: String,
    used_by_repositories: i64,
}

impl SshKeySummary {
    pub fn of(key: &KeyView) -> SshKeySummary {
        SshKeySummary {
            id: key.id.as_hyphenated().to_string(),
            name: key.name.clone(),
            public_key: key.public_key.clone(),
            created_at: instant(key.created_at),
            encryption_state: key.encryption_state.clone(),
            used_by_repositories: key.used_by_repositories,
        }
    }
}
