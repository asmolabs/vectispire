//! The targets as the layers above the services hold them: the rows' properties under their own names, not the rows
//! — `RepositoryView`, `ContainerView`, `SolutionView`, `ProjectView`.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::persistence::{ContainerRow, ProjectRow, RepositoryRow, SolutionRow};

/// A monitored repository. `badge_token` is left out: it is the capability an anonymous badge is served under, and
/// nothing that reads a repository through this has a use for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryView {
    pub id: i64,
    pub url: String,
    pub branch: String,
    pub sub_path: Option<String>,
    pub name: Option<String>,
    pub scan_interval_minutes: Option<i32>,
    pub scan_cron: Option<String>,
    pub scan_manual_only: bool,
    pub required_agent_label: Option<String>,
    pub last_scheduled_scan_at: Option<OffsetDateTime>,
    pub ssh_key_id: Option<Uuid>,
    pub https_token_id: Option<Uuid>,
    pub tier: String,
    pub in_certified_scope: bool,
    pub project_id: Option<i64>,
}

impl From<&RepositoryRow> for RepositoryView {
    fn from(row: &RepositoryRow) -> RepositoryView {
        RepositoryView {
            id: row.id,
            url: row.url.clone(),
            branch: row.branch.clone(),
            sub_path: row.sub_path.clone(),
            name: row.name.clone(),
            scan_interval_minutes: row.scan_interval_minutes,
            scan_cron: row.scan_cron.clone(),
            scan_manual_only: row.scan_manual_only,
            required_agent_label: row.required_agent_label.clone(),
            last_scheduled_scan_at: row.last_scheduled_scan_at,
            ssh_key_id: row.ssh_key_id,
            https_token_id: row.https_token_id,
            tier: row.tier.clone(),
            in_certified_scope: row.in_certified_scope,
            project_id: row.project_id,
        }
    }
}

/// A watched container image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerView {
    pub id: i64,
    pub registry: Option<String>,
    pub image_name: String,
    pub tag: String,
    pub scan_interval_minutes: Option<i32>,
    pub scan_cron: Option<String>,
    pub scan_manual_only: bool,
    pub required_agent_label: Option<String>,
    pub last_scheduled_scan_at: Option<OffsetDateTime>,
    pub tier: String,
    pub in_certified_scope: bool,
    pub project_id: Option<i64>,
}

impl From<&ContainerRow> for ContainerView {
    fn from(row: &ContainerRow) -> ContainerView {
        ContainerView {
            id: row.id,
            registry: row.registry.clone(),
            image_name: row.image_name.clone(),
            tag: row.tag.clone(),
            scan_interval_minutes: row.scan_interval_minutes,
            scan_cron: row.scan_cron.clone(),
            scan_manual_only: row.scan_manual_only,
            required_agent_label: row.required_agent_label.clone(),
            last_scheduled_scan_at: row.last_scheduled_scan_at,
            tier: row.tier.clone(),
            in_certified_scope: row.in_certified_scope,
            project_id: row.project_id,
        }
    }
}

/// `SolutionView`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolutionView {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
}

impl From<&SolutionRow> for SolutionView {
    fn from(row: &SolutionRow) -> SolutionView {
        SolutionView {
            id: row.id,
            name: row.name.clone(),
            description: row.description.clone(),
            created_at: row.created_at,
        }
    }
}

/// `ProjectView`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectView {
    pub id: i64,
    pub solution_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
}

impl From<&ProjectRow> for ProjectView {
    fn from(row: &ProjectRow) -> ProjectView {
        ProjectView {
            id: row.id,
            solution_id: row.solution_id,
            name: row.name.clone(),
            description: row.description.clone(),
            created_at: row.created_at,
        }
    }
}
