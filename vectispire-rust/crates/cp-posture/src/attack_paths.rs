//! `AttackPathService`: a repository's attack-path graph, and the overview of every repository the caller sees —
//! three reads for a page (repositories, endpoints, open issues), the drawing in [`crate::attack_path`].

use std::collections::BTreeMap;
use std::sync::Arc;

use vectispire_cp_access::rows;
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_inventory::ApiInventoryService;
use vectispire_cp_issues::IssueCatalog;
use vectispire_cp_issues::queries::GraphNode;
use vectispire_cp_targets::Targets;
use vectispire_cp_targets::views::RepositoryView;
use vectispire_domain::list_window::ListWindow;
use vectispire_domain::repository_url;
use vectispire_domain::triage_status::TriageStatus;

use crate::attack_path::{AttackPathGraph, Endpoint, GraphIssue, build_graph};
use crate::error::PostureError;

#[derive(Clone)]
pub struct AttackPaths {
    targets: Arc<Targets>,
    apis: Arc<ApiInventoryService>,
    issues: Arc<IssueCatalog>,
}

opaque_debug!(AttackPaths);

fn graph_issue(row: GraphNode) -> GraphIssue {
    GraphIssue {
        id: Some(row.id),
        repo_id: row.repo_id,
        type_: Some(row.type_),
        severity: row.severity,
        identifier: row.identifier,
        description: row.description,
        package_name: row.package_name,
        package_version: row.package_version,
        file_path: row.file_path,
        cvss_score: row.cvss_score,
        epss_score: row.epss_score,
        is_kev: Some(row.is_kev),
    }
}

impl AttackPaths {
    pub fn new(targets: Arc<Targets>, apis: Arc<ApiInventoryService>, issues: Arc<IssueCatalog>) -> AttackPaths {
        AttackPaths { targets, apis, issues }
    }

    /// One repository's graph; a hidden one refused as an absent target, an absent one the caller could see `None`.
    pub async fn graph(&self, repository: i64, allowed: &Visibility) -> Result<Option<AttackPathGraph>, PostureError> {
        rows::require_visible(ScanTarget::Repository(repository), allowed)?;
        let Some(found) = self.targets.catalog_repository(repository).await.map_err(PostureError::unexpected)? else {
            return Ok(None);
        };
        let endpoints = self.endpoints(repository, allowed).await?;
        let issues = self.open_issues(&[repository]).await?;
        Ok(Some(Self::draw(&found, &endpoints, issues.get(&repository).map(Vec::as_slice).unwrap_or_default())))
    }

    /// Every repository the caller sees, by id; with `limit`, one page of them.
    pub async fn overview(
        &self,
        allowed: &Visibility,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<AttackPathGraph>, PostureError> {
        let window = ListWindow::requested(limit, offset).map_err(PostureError::Invalid)?;
        let mut permitted: Vec<RepositoryView> = match allowed {
            Visibility::Everything => self.targets.catalog_repositories().await.map_err(PostureError::unexpected)?,
            Visibility::Only(targets) => {
                let ids = targets
                    .iter()
                    .filter_map(|target| match target {
                        ScanTarget::Repository(id) => Some(*id),
                        ScanTarget::Container(_) => None,
                    })
                    .collect();
                self.targets.catalog_repositories_by_ids(&ids).await.map_err(PostureError::unexpected)?
            }
        };
        permitted.sort_by_key(|repository| repository.id);
        let visible = match window {
            Some(window) => window.of(&permitted),
            None => permitted,
        };
        if visible.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<i64> = visible.iter().map(|repository| repository.id).collect();
        let issues = self.open_issues(&ids).await?;
        let mut graphs = Vec::new();
        for repository in &visible {
            let endpoints = self.endpoints(repository.id, allowed).await?;
            graphs.push(Self::draw(
                repository,
                &endpoints,
                issues.get(&repository.id).map(Vec::as_slice).unwrap_or_default(),
            ));
        }
        Ok(graphs)
    }

    fn draw(repository: &RepositoryView, endpoints: &[Endpoint], issues: &[GraphIssue]) -> AttackPathGraph {
        // The repository's own name, else its URL with any credential cut out.
        let name = repository.name.clone().unwrap_or_else(|| repository_url::redact(&repository.url));
        build_graph(repository.id, name, endpoints, issues)
    }

    async fn endpoints(&self, repository: i64, allowed: &Visibility) -> Result<Vec<Endpoint>, PostureError> {
        let overview = self.apis.for_repository(repository, allowed).await.map_err(PostureError::unexpected)?;
        Ok(overview
            .endpoints
            .into_iter()
            .map(|view| Endpoint {
                id: view.id,
                method: view.method,
                path: view.path,
                auth_required: view.auth_required,
                visibility: view.visibility,
                file_path: view.file_path,
                framework: view.framework,
            })
            .collect())
    }

    /// The open issues of these repositories that no settled triage took out of the picture, by repository.
    async fn open_issues(&self, repositories: &[i64]) -> Result<BTreeMap<i64, Vec<GraphIssue>>, PostureError> {
        let settled = TriageStatus::settled_wire_names();
        let rows = self
            .issues
            .unsettled_of_repositories("open", repositories, settled)
            .await
            .map_err(PostureError::unexpected)?;
        let mut by_repository: BTreeMap<i64, Vec<GraphIssue>> = BTreeMap::new();
        for row in rows {
            if let Some(repository) = row.repo_id {
                by_repository.entry(repository).or_default().push(graph_issue(row));
            }
        }
        Ok(by_repository)
    }
}
