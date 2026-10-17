//! `SolutionQueryService`: the solutions tree and a project's detail, **as far as the caller sees them**, and the
//! scopes other modules check a project or a solution against.
//!
//! A reader sees a project when everything is visible to them, when the project was granted as such, or when one of
//! its targets is visible; a solution, when one of its projects is shown. Figures are summed over the visible targets
//! only, and `partial` says that some were not — a reader of half a project is told so rather than shown a
//! half-figure as the whole.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use vectispire_cp_access::Allowance;
use vectispire_cp_access::rows::{self, VisibleScope};
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_domain::{Severity, java};

use crate::error::TargetError;
use crate::persistence::{self, ContainerRow, ProjectRow, RepositoryRow, StoreError};
use crate::{Targets, naming};

/// Open issues by severity, and their total.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenIssues {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub negligible: i64,
    pub unknown: i64,
    pub total: i64,
}

impl OpenIssues {
    fn of(counts: &BTreeMap<Severity, i64>) -> OpenIssues {
        let get = |severity| counts.get(&severity).copied().unwrap_or(0);
        let (critical, high, medium, low, negligible, unknown) = (
            get(Severity::Critical),
            get(Severity::High),
            get(Severity::Medium),
            get(Severity::Low),
            get(Severity::Negligible),
            get(Severity::Unknown),
        );
        OpenIssues {
            critical,
            high,
            medium,
            low,
            negligible,
            unknown,
            total: critical + high + medium + low + negligible + unknown,
        }
    }

    fn add(self, other: OpenIssues) -> OpenIssues {
        OpenIssues {
            critical: self.critical + other.critical,
            high: self.high + other.high,
            medium: self.medium + other.medium,
            low: self.low + other.low,
            negligible: self.negligible + other.negligible,
            unknown: self.unknown + other.unknown,
            total: self.total + other.total,
        }
    }
}

/// A target as the tree names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRef {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectNode {
    pub id: i64,
    pub solution_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: time::OffsetDateTime,
    pub partial: bool,
    /// Whether the caller sees the project whole — the checklists' guard (`seesWholeProject`).
    pub checklists_visible: bool,
    pub repository_count: i64,
    pub open_issues: OpenIssues,
    pub repositories: Vec<TargetRef>,
    /// The union of the visible repositories' known languages, as wire names in `Language`'s order.
    pub detected_languages: Vec<String>,
    /// The visible repositories whose languages are unknown, ascending.
    pub languages_unknown_for: Vec<i64>,
    pub container_count: i64,
    pub containers: Vec<TargetRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolutionNode {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: time::OffsetDateTime,
    pub partial: bool,
    pub repository_count: i64,
    pub open_issues: OpenIssues,
    pub projects: Vec<ProjectNode>,
    pub container_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unfiled {
    pub repository_count: i64,
    pub open_issues: OpenIssues,
    pub repositories: Vec<TargetRef>,
    pub container_count: i64,
    pub containers: Vec<TargetRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolutionTree {
    pub solutions: Vec<SolutionNode>,
    pub unfiled: Unfiled,
}

/// A project's detail: its node, and its solution by id and name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDetail {
    pub node: ProjectNode,
    pub solution_name: Option<String>,
}

/// A project and what is filed in it — every target, visible or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectMembers {
    pub project_id: i64,
    pub name: String,
    pub repository_ids: Vec<i64>,
    pub container_ids: Vec<i64>,
}

impl ProjectMembers {
    pub fn targets(&self) -> Vec<ScanTarget> {
        self.repository_ids
            .iter()
            .map(|id| ScanTarget::Repository(*id))
            .chain(self.container_ids.iter().map(|id| ScanTarget::Container(*id)))
            .collect()
    }
}

/// `String.CASE_INSENSITIVE_ORDER` — the tree's order; Rust's would sort `ß` and `İ` elsewhere.
fn by_name(left: &str, right: &str) -> Ordering {
    java::compare_ignore_case(left, right)
}

impl Targets {
    /// The tree, as far as `allowance` sees it.
    pub async fn tree(&self, allowance: &Allowance) -> Result<SolutionTree, TargetError> {
        let visibility = &allowance.visibility;
        let everything = matches!(visibility, Visibility::Everything);
        let mut tx = persistence::read(&self.db).await?;
        let all_repositories = persistence::repositories(&mut tx).await?;
        let all_containers = persistence::containers(&mut tx).await?;
        let all_projects = persistence::projects(&mut tx).await?;
        let all_solutions = persistence::solutions(&mut tx).await?;
        tx.commit().await.map_err(StoreError::from)?;

        let visible: Vec<&RepositoryRow> =
            all_repositories.iter().filter(|row| visibility.permits(ScanTarget::Repository(row.id))).collect();
        let visible_containers: Vec<&ContainerRow> =
            all_containers.iter().filter(|row| visibility.permits(ScanTarget::Container(row.id))).collect();
        let visible_by_project = group(&visible, |row| row.project_id);
        let containers_by_project = group(&visible_containers, |row| row.project_id);
        // Every filed target, visible or not, per project: what `partial` is measured against.
        let mut filed_by_project: BTreeMap<i64, i64> = BTreeMap::new();
        for project in all_repositories
            .iter()
            .filter_map(|row| row.project_id)
            .chain(all_containers.iter().filter_map(|row| row.project_id))
        {
            *filed_by_project.entry(project).or_default() += 1;
        }
        // Every filed repository, visible or not: what the checklists' guard compares.
        let mut repository_ids_by_project: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
        for row in &all_repositories {
            if let Some(project) = row.project_id {
                repository_ids_by_project.entry(project).or_default().push(row.id);
            }
        }
        let open = self.open_by_severity(&visible, &visible_containers, everything).await?;
        // Of the repositories filed in a project and visible: an unfiled one belongs to no project's union, and a
        // hidden one's languages are its own.
        let filed_visible: Vec<i64> = visible.iter().filter(|row| row.project_id.is_some()).map(|row| row.id).collect();
        let languages = self.scans.detected_languages(&filed_visible).await.map_err(TargetError::Unexpected)?;

        let mut nodes_by_solution: BTreeMap<i64, Vec<ProjectNode>> = BTreeMap::new();
        let mut shown: Vec<ProjectNode> = all_projects
            .iter()
            .filter(|project| {
                everything
                    || allowance.granted_projects.contains(&project.id)
                    || visible_by_project.contains_key(&Some(project.id))
                    || containers_by_project.contains_key(&Some(project.id))
            })
            .map(|project| {
                project_node(
                    project,
                    visible_by_project.get(&Some(project.id)).map_or(&[][..], Vec::as_slice),
                    containers_by_project.get(&Some(project.id)).map_or(&[][..], Vec::as_slice),
                    filed_by_project.get(&project.id).copied().unwrap_or(0),
                    rows::sees_whole_project(
                        project.id,
                        repository_ids_by_project.get(&project.id).map_or(&[][..], Vec::as_slice),
                        allowance,
                    ),
                    &open,
                    &languages,
                )
            })
            .collect();
        // Stable, as `Stream.sorted` is: names that compare equal keep the table's order.
        shown.sort_by(|left, right| by_name(&left.name, &right.name));
        for node in shown {
            nodes_by_solution.entry(node.solution_id).or_default().push(node);
        }
        // Hidden targets per solution, over every project of it and not only the shown ones: a project the reader
        // cannot see at all still makes the solution's figures partial.
        let solution_of_project: BTreeMap<i64, i64> =
            all_projects.iter().map(|project| (project.id, project.solution_id)).collect();
        let mut filed_by_solution: BTreeMap<i64, i64> = BTreeMap::new();
        for (project, count) in &filed_by_project {
            if let Some(solution) = solution_of_project.get(project) {
                *filed_by_solution.entry(*solution).or_default() += count;
            }
        }
        let shown_solutions: Vec<_> = all_solutions
            .iter()
            .filter(|solution| everything || nodes_by_solution.contains_key(&solution.id))
            .collect();
        let mut solutions: Vec<SolutionNode> = shown_solutions
            .into_iter()
            .map(|solution| {
                let projects = nodes_by_solution.remove(&solution.id).unwrap_or_default();
                let repositories: i64 = projects.iter().map(|node| node.repository_count).sum();
                let containers: i64 = projects.iter().map(|node| node.container_count).sum();
                SolutionNode {
                    id: solution.id,
                    name: solution.name.clone(),
                    description: solution.description.clone(),
                    created_at: solution.created_at,
                    partial: repositories + containers < filed_by_solution.get(&solution.id).copied().unwrap_or(0),
                    repository_count: repositories,
                    open_issues: projects.iter().fold(OpenIssues::default(), |sum, node| sum.add(node.open_issues)),
                    projects,
                    container_count: containers,
                }
            })
            .collect();
        solutions.sort_by(|left, right| by_name(&left.name, &right.name));

        let unfiled = visible_by_project.get(&None).map_or(&[][..], Vec::as_slice);
        let unfiled_containers = containers_by_project.get(&None).map_or(&[][..], Vec::as_slice);
        Ok(SolutionTree {
            solutions,
            unfiled: Unfiled {
                repository_count: count(unfiled.len()),
                open_issues: sum(unfiled, unfiled_containers, &open),
                repositories: refs(unfiled),
                container_count: count(unfiled_containers.len()),
                containers: container_refs(unfiled_containers),
            },
        })
    }

    /// A project as far as `allowance` sees it, or "Project not found." — absent and hidden alike.
    pub async fn project_detail(&self, project_id: i64, allowance: &Allowance) -> Result<ProjectDetail, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let project = persistence::project(&mut tx, project_id).await?;
        let (filed_repositories, filed_containers) = match &project {
            Some(found) => (
                persistence::repositories_of_project(&mut tx, found.id).await?,
                persistence::containers_of_project(&mut tx, found.id).await?,
            ),
            None => (Vec::new(), Vec::new()),
        };
        let solution = match &project {
            Some(found) => persistence::solution(&mut tx, found.solution_id).await?,
            None => None,
        };
        tx.commit().await.map_err(StoreError::from)?;
        let filed: Vec<ScanTarget> = filed_repositories
            .iter()
            .map(|row| ScanTarget::Repository(row.id))
            .chain(filed_containers.iter().map(|row| ScanTarget::Container(row.id)))
            .collect();
        let scope = rows::require_visible_project(
            project_id,
            project.as_ref().map(|found| found.name.as_str()),
            &filed,
            allowance,
        )?;
        let Some(project) = project else {
            return Err(TargetError::not_found(rows::PROJECT_NOT_FOUND));
        };
        let seen: BTreeSet<ScanTarget> = scope.visible.iter().copied().collect();
        let visible: Vec<&RepositoryRow> =
            filed_repositories.iter().filter(|row| seen.contains(&ScanTarget::Repository(row.id))).collect();
        let visible_containers: Vec<&ContainerRow> =
            filed_containers.iter().filter(|row| seen.contains(&ScanTarget::Container(row.id))).collect();
        // Narrowed to the project's visible targets, written into the statement: the backlog is asked about this
        // project alone, never about the estate and then filtered.
        let open = if seen.is_empty() {
            BTreeMap::new()
        } else {
            self.backlog
                .open_by_severity_per_target(&Visibility::Only(seen.clone()))
                .await
                .map_err(TargetError::Unexpected)?
        };
        let ids: Vec<i64> = visible.iter().map(|row| row.id).collect();
        let languages = self.scans.detected_languages(&ids).await.map_err(TargetError::Unexpected)?;
        let repository_ids: Vec<i64> = filed_repositories.iter().map(|row| row.id).collect();
        let node = project_node(
            &project,
            &visible,
            &visible_containers,
            count(filed_repositories.len() + filed_containers.len()),
            rows::sees_whole_project(project_id, &repository_ids, allowance),
            &open,
            &languages,
        );
        Ok(ProjectDetail { node, solution_name: solution.map(|solution| solution.name) })
    }

    /// A project and what is filed in it, visible or not.
    pub async fn members(&self, project_id: i64) -> Result<Option<ProjectMembers>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let Some(project) = persistence::project(&mut tx, project_id).await? else {
            tx.commit().await.map_err(StoreError::from)?;
            return Ok(None);
        };
        let repository_ids = persistence::repository_ids_in_projects(&mut tx, &[project.id]).await?;
        let container_ids = persistence::container_ids_in_projects(&mut tx, &[project.id]).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(Some(ProjectMembers { project_id: project.id, name: project.name, repository_ids, container_ids }))
    }

    /// The project a repository is filed in; `None` for an absent repository, `Some(None)` for an unfiled one.
    pub async fn project_of(&self, repository_id: i64) -> Result<Option<Option<i64>>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let found = persistence::repository(&mut tx, repository_id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(found.map(|row| row.project_id))
    }

    /// Every target filed under a solution's projects.
    pub async fn targets_of_solution(&self, solution_id: i64) -> Result<Vec<ScanTarget>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let repositories = persistence::repository_ids_of_solution(&mut tx, solution_id).await?;
        let containers = persistence::container_ids_of_solution(&mut tx, solution_id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(repositories
            .into_iter()
            .map(ScanTarget::Repository)
            .chain(containers.into_iter().map(ScanTarget::Container))
            .collect())
    }

    /// `visibleProject`: the project's scope, or "Project not found.".
    pub async fn visible_project(&self, project_id: i64, allowance: &Allowance) -> Result<VisibleScope, TargetError> {
        let members = self.members(project_id).await?;
        let filed = members.as_ref().map(ProjectMembers::targets).unwrap_or_default();
        Ok(rows::require_visible_project(
            project_id,
            members.as_ref().map(|found| found.name.as_str()),
            &filed,
            allowance,
        )?)
    }

    /// `visibleSolution`: the solution's scope, or "Solution not found.".
    pub async fn visible_solution(&self, solution_id: i64, allowance: &Allowance) -> Result<VisibleScope, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let solution = persistence::solution(&mut tx, solution_id).await?;
        let projects: Vec<i64> = match &solution {
            Some(found) => {
                persistence::projects_of_solution(&mut tx, found.id).await?.iter().map(|project| project.id).collect()
            }
            None => Vec::new(),
        };
        tx.commit().await.map_err(StoreError::from)?;
        let filed = match &solution {
            Some(found) => self.targets_of_solution(found.id).await?,
            None => Vec::new(),
        };
        Ok(rows::require_visible_solution(
            solution_id,
            solution.as_ref().map(|found| found.name.as_str()),
            &projects,
            &filed,
            allowance,
        )?)
    }

    async fn open_by_severity(
        &self,
        visible: &[&RepositoryRow],
        visible_containers: &[&ContainerRow],
        everything: bool,
    ) -> Result<BTreeMap<ScanTarget, BTreeMap<Severity, i64>>, TargetError> {
        if !everything && visible.is_empty() && visible_containers.is_empty() {
            return Ok(BTreeMap::new());
        }
        let narrowed = if everything {
            Visibility::Everything
        } else {
            Visibility::only(
                visible
                    .iter()
                    .map(|row| ScanTarget::Repository(row.id))
                    .chain(visible_containers.iter().map(|row| ScanTarget::Container(row.id))),
            )
        };
        self.backlog.open_by_severity_per_target(&narrowed).await.map_err(TargetError::Unexpected)
    }
}

fn count(length: usize) -> i64 {
    i64::try_from(length).unwrap_or(i64::MAX)
}

fn group<'a, T>(rows: &[&'a T], project_of: impl Fn(&T) -> Option<i64>) -> BTreeMap<Option<i64>, Vec<&'a T>> {
    let mut grouped: BTreeMap<Option<i64>, Vec<&'a T>> = BTreeMap::new();
    for row in rows {
        grouped.entry(project_of(row)).or_default().push(row);
    }
    grouped
}

fn project_node(
    project: &ProjectRow,
    visible: &[&RepositoryRow],
    visible_containers: &[&ContainerRow],
    filed: i64,
    checklists_visible: bool,
    open: &BTreeMap<ScanTarget, BTreeMap<Severity, i64>>,
    languages: &BTreeMap<i64, BTreeSet<String>>,
) -> ProjectNode {
    let mut union: BTreeSet<String> = BTreeSet::new();
    let mut unknown: Vec<i64> = Vec::new();
    for row in visible {
        match languages.get(&row.id) {
            None => unknown.push(row.id),
            Some(known) => union.extend(known.iter().cloned()),
        }
    }
    unknown.sort_unstable();
    ProjectNode {
        id: project.id,
        solution_id: project.solution_id,
        name: project.name.clone(),
        description: project.description.clone(),
        created_at: project.created_at,
        partial: count(visible.len() + visible_containers.len()) < filed,
        checklists_visible,
        repository_count: count(visible.len()),
        open_issues: sum(visible, visible_containers, open),
        repositories: refs(visible),
        detected_languages: union.into_iter().collect(),
        languages_unknown_for: unknown,
        container_count: count(visible_containers.len()),
        containers: container_refs(visible_containers),
    }
}

/// The open figures of these targets, summed; all zero (`OpenIssues.NONE`) when none has any.
fn sum(
    repositories: &[&RepositoryRow],
    containers: &[&ContainerRow],
    open: &BTreeMap<ScanTarget, BTreeMap<Severity, i64>>,
) -> OpenIssues {
    let mut total: BTreeMap<Severity, i64> = BTreeMap::new();
    let targets = repositories
        .iter()
        .map(|row| ScanTarget::Repository(row.id))
        .chain(containers.iter().map(|row| ScanTarget::Container(row.id)));
    for target in targets {
        if let Some(counts) = open.get(&target) {
            for (severity, count) in counts {
                *total.entry(*severity).or_default() += count;
            }
        }
    }
    OpenIssues::of(&total)
}

/// By name without case, then by identifier.
fn refs(rows: &[&RepositoryRow]) -> Vec<TargetRef> {
    let mut refs: Vec<TargetRef> =
        rows.iter().map(|row| TargetRef { id: row.id, name: naming::of_repository(row) }).collect();
    refs.sort_by(|left, right| by_name(&left.name, &right.name).then(left.id.cmp(&right.id)));
    refs
}

fn container_refs(rows: &[&ContainerRow]) -> Vec<TargetRef> {
    let mut refs: Vec<TargetRef> =
        rows.iter().map(|row| TargetRef { id: row.id, name: naming::of_container(row) }).collect();
    refs.sort_by(|left, right| by_name(&left.name, &right.name).then(left.id.cmp(&right.id)));
    refs
}
