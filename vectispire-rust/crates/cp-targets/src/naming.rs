//! `TargetNaming`: what a target is called on a screen, in an alert and in a ticket — one place, because a name
//! computed three ways is three names for one thing, and the mismatch surfaces where it costs most.

use std::collections::{BTreeMap, BTreeSet};

use vectispire_cp_db::{Db, Tx};
use vectispire_domain::image_reference::ImageReference;
use vectispire_domain::repository_url;

use crate::persistence::{self, ContainerRow, ProjectRow, RepositoryRow, SolutionRow, StoreError};
use crate::views::{ContainerView, RepositoryView};

/// Said explicitly rather than shown as a blank: a scan's history stays useful after its target is gone.
pub const DELETED: &str = "deleted target";

/// The operator's name for a repository, or the short form of its URL when they gave none — through the domain's
/// rule, so that the same repository is never called two things on two screens.
pub fn repository_name(name: Option<&str>, url: &str) -> String {
    repository_url::display_name(name, url)
}

pub fn of_repository(row: &RepositoryRow) -> String {
    repository_name(row.name.as_deref(), &row.url)
}

pub fn of_repository_view(view: &RepositoryView) -> String {
    repository_name(view.name.as_deref(), &view.url)
}

/// `name:tag`.
pub fn of_container(row: &ContainerRow) -> String {
    ImageReference::new(row.registry.as_deref(), Some(&row.image_name), Some(&row.tag)).display_name()
}

pub fn of_container_view(view: &ContainerView) -> String {
    ImageReference::new(view.registry.as_deref(), Some(&view.image_name), Some(&view.tag)).display_name()
}

/// `Solution / Project`, or the project's name alone should its solution be unreadable — qualified because a
/// project's name is unique only within its solution.
pub fn of_project(project: &ProjectRow, solution: Option<&SolutionRow>) -> String {
    match solution {
        Some(solution) => format!("{} / {}", solution.name, project.name),
        None => project.name.clone(),
    }
}

/// Names for a known set of identifiers, both kinds resolved in one pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names {
    pub repositories: BTreeMap<i64, String>,
    pub containers: BTreeMap<i64, String>,
}

impl Names {
    /// The repository's name when `repository` is set, else the image's; [`DELETED`] for one that is gone.
    pub fn of(&self, repository: Option<i64>, container: Option<i64>) -> String {
        match (repository, container) {
            (Some(id), _) => self.repositories.get(&id).cloned().unwrap_or_else(|| DELETED.to_owned()),
            (None, Some(id)) => self.containers.get(&id).cloned().unwrap_or_else(|| DELETED.to_owned()),
            (None, None) => DELETED.to_owned(),
        }
    }
}

/// `projectNames`: each project's `Solution / Project`, those that exist.
pub async fn project_names(tx: &mut Tx, project_ids: &BTreeSet<i64>) -> Result<BTreeMap<i64, String>, StoreError> {
    if project_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let ids: Vec<i64> = project_ids.iter().copied().collect();
    let projects = persistence::projects_by_ids(tx, &ids).await?;
    let solution_ids: BTreeSet<i64> = projects.iter().map(|project| project.solution_id).collect();
    let solutions: BTreeMap<i64, SolutionRow> =
        persistence::solutions_by_ids(tx, &solution_ids.into_iter().collect::<Vec<_>>())
            .await?
            .into_iter()
            .map(|solution| (solution.id, solution))
            .collect();
    Ok(projects.iter().map(|project| (project.id, of_project(project, solutions.get(&project.solution_id)))).collect())
}

/// `forIds`: the names of these targets, those that exist, a thousand identifiers per statement.
pub async fn for_ids(db: &Db, repositories: &BTreeSet<i64>, containers: &BTreeSet<i64>) -> Result<Names, StoreError> {
    let mut tx = persistence::read(db).await?;
    let repositories =
        persistence::repositories_by_ids(&mut tx, &repositories.iter().copied().collect::<Vec<_>>()).await?;
    let containers = persistence::containers_by_ids(&mut tx, &containers.iter().copied().collect::<Vec<_>>()).await?;
    tx.commit().await.map_err(StoreError::from)?;
    Ok(Names {
        repositories: repositories.iter().map(|row| (row.id, of_repository(row))).collect(),
        containers: containers.iter().map(|row| (row.id, of_container(row))).collect(),
    })
}

/// `all`: every target's name, in two statements — a list of two hundred scans would otherwise issue two hundred.
pub async fn all(db: &Db) -> Result<Names, StoreError> {
    let mut tx = persistence::read(db).await?;
    let repositories = persistence::repositories(&mut tx).await?;
    let containers = persistence::containers(&mut tx).await?;
    tx.commit().await.map_err(StoreError::from)?;
    Ok(Names {
        repositories: repositories.iter().map(|row| (row.id, of_repository(row))).collect(),
        containers: containers.iter().map(|row| (row.id, of_container(row))).collect(),
    })
}
