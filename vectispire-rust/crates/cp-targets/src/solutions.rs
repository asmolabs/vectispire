//! `SolutionAdministrationService`: solutions, their projects, and which project a repository or an image is filed
//! in (decision 0023) — which is also who sees it through a project grant.

use std::collections::BTreeMap;

use vectispire_cp_access::rows;
use vectispire_cp_audit::{AuditOperation, Record, RequestActor};
use vectispire_cp_db::{ScanTarget, Tx, Visibility};
use vectispire_domain::bounded_text;

use crate::audit::ACCESS_GRANT_CHANGED;
use crate::error::TargetError;
use crate::persistence::{self, ProjectRow, SolutionRow, StoreError};
use crate::views::{ProjectView, SolutionView};
use crate::{Targets, naming};

pub const NAME_LENGTH: usize = 100;
pub const DESCRIPTION_LENGTH: usize = 255;

/// The problem types of the two name conflicts.
pub const SOLUTION_NAME_TAKEN: &str = "solution-name-taken";
pub const PROJECT_NAME_TAKEN: &str = "project-name-taken";

/// A project as another module labels it: its name and its solution's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectLabel {
    pub id: i64,
    pub name: String,
    pub solution_id: i64,
    pub solution_name: Option<String>,
}

impl Targets {
    // ── solutions ────────────────────────────────────────────────────────────────────────

    pub async fn create_solution(
        &self,
        name: Option<&str>,
        description: Option<&str>,
        actor: &RequestActor,
    ) -> Result<SolutionView, TargetError> {
        let mut entries = Vec::new();
        let mut tx = persistence::write(&self.db).await?;
        let created = self.create_solution_in(&mut tx, name, description, actor, &mut entries).await;
        let created = finish(tx, created).await?;
        self.record_all(entries).await;
        Ok(created)
    }

    /// The creation inside a transaction the caller holds, its entry handed to `entries` to be recorded once the
    /// transaction has committed — the import's batch form.
    pub(crate) async fn create_solution_in(
        &self,
        tx: &mut Tx,
        name: Option<&str>,
        description: Option<&str>,
        actor: &RequestActor,
        entries: &mut Vec<Record>,
    ) -> Result<SolutionView, TargetError> {
        let name = bounded_text::required(name, NAME_LENGTH, "A solution name")?;
        refuse_if_solution_name_taken(tx, &name, None).await?;
        let mut row = SolutionRow {
            id: 0,
            name: name.clone(),
            description: bounded_text::optional(description, DESCRIPTION_LENGTH, "The description")?,
            created_at: self.clock.now(),
        };
        row.id = persistence::insert_solution(tx, &row).await?;
        entries.push(actor.entry(
            AuditOperation::SolutionUpdated,
            &row.id.to_string(),
            &format!("Solution created: {name}"),
        ));
        Ok(SolutionView::from(&row))
    }

    pub async fn update_solution(
        &self,
        id: i64,
        name: Option<&str>,
        description: Option<&str>,
        actor: &RequestActor,
    ) -> Result<SolutionView, TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let mut row = require_solution(&mut tx, id).await?;
            let previous = row.name.clone();
            if name.is_some() {
                let name = bounded_text::required(name, NAME_LENGTH, "A solution name")?;
                refuse_if_solution_name_taken(&mut tx, &name, Some(id)).await?;
                row.name = name;
            }
            if description.is_some() {
                row.description = bounded_text::optional(description, DESCRIPTION_LENGTH, "The description")?;
            }
            persistence::update_solution(&mut tx, &row).await?;
            Ok::<_, TargetError>((row, previous))
        }
        .await;
        let (row, previous) = finish(tx, outcome).await?;
        let renamed = if previous == row.name { String::new() } else { format!(" → {}", row.name) };
        self.audit
            .record(actor.entry(
                AuditOperation::SolutionUpdated,
                &id.to_string(),
                &format!("Solution {previous} updated{renamed}"),
            ))
            .await;
        Ok(SolutionView::from(&row))
    }

    /// Refused while it holds projects (409): deleting it would orphan them.
    pub async fn delete_solution(&self, id: i64, actor: &RequestActor) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let row = require_solution(&mut tx, id).await?;
            let held = persistence::count_projects_of_solution(&mut tx, id).await?;
            if held > 0 {
                return Err(TargetError::Conflict {
                    message: format!(
                        "The solution {} still holds {held} project(s). Move them to another solution or delete them \
                         first.",
                        row.name
                    ),
                    cause: None,
                    members: Vec::new(),
                });
            }
            persistence::delete_solution(&mut tx, id).await?;
            Ok::<_, TargetError>(row)
        }
        .await;
        let row = finish(tx, outcome).await?;
        self.audit
            .record(actor.entry(
                AuditOperation::SolutionUpdated,
                &id.to_string(),
                &format!("Solution deleted: {}", row.name),
            ))
            .await;
        Ok(())
    }

    // ── projects ─────────────────────────────────────────────────────────────────────────

    pub async fn create_project(
        &self,
        solution_id: i64,
        name: Option<&str>,
        description: Option<&str>,
        actor: &RequestActor,
    ) -> Result<ProjectView, TargetError> {
        let mut entries = Vec::new();
        let mut tx = persistence::write(&self.db).await?;
        let created = self.create_project_in(&mut tx, solution_id, name, description, actor, &mut entries).await;
        let created = finish(tx, created).await?;
        self.record_all(entries).await;
        Ok(created)
    }

    pub(crate) async fn create_project_in(
        &self,
        tx: &mut Tx,
        solution_id: i64,
        name: Option<&str>,
        description: Option<&str>,
        actor: &RequestActor,
        entries: &mut Vec<Record>,
    ) -> Result<ProjectView, TargetError> {
        let solution = require_solution(tx, solution_id).await?;
        let name = bounded_text::required(name, NAME_LENGTH, "A project name")?;
        refuse_if_project_name_taken(tx, solution_id, &name, None).await?;
        let mut row = ProjectRow {
            id: 0,
            solution_id,
            name: name.clone(),
            description: bounded_text::optional(description, DESCRIPTION_LENGTH, "The description")?,
            created_at: self.clock.now(),
        };
        row.id = persistence::insert_project(tx, &row).await?;
        entries.push(actor.entry(
            AuditOperation::ProjectUpdated,
            &row.id.to_string(),
            &format!("Project created: {} / {name}", solution.name),
        ));
        Ok(ProjectView::from(&row))
    }

    /// The solution of that name, case aside — reused by an import rather than created twice.
    pub async fn solution_named(&self, name: &str) -> Result<Option<SolutionView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let found = persistence::solution_named(&mut tx, name).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(found.as_ref().map(SolutionView::from))
    }

    /// The project of that name in the solution, case aside.
    pub async fn project_named(&self, solution_id: i64, name: &str) -> Result<Option<ProjectView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let found = persistence::project_named(&mut tx, solution_id, name).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(found.as_ref().map(ProjectView::from))
    }

    /// Renames, describes, or moves a project to another solution. **Moving is an administrator's whole gesture**:
    /// a caller who does not see everything is answered as if the target solution did not exist — the project's
    /// repositories, images, grants and checklists all follow it.
    pub async fn update_project(
        &self,
        id: i64,
        name: Option<&str>,
        description: Option<&str>,
        solution_id: Option<i64>,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<ProjectView, TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let mut row = require_project(&mut tx, id).await?;
            let previous = row.name.clone();
            let previous_solution = row.solution_id;
            let mut target = None;
            if let Some(solution_id) = solution_id.filter(|solution_id| *solution_id != previous_solution) {
                if !matches!(allowed, Visibility::Everything) {
                    return Err(TargetError::not_found(rows::SOLUTION_NOT_FOUND));
                }
                target = Some(require_solution(&mut tx, solution_id).await?);
            }
            let new_name = match name {
                None => previous.clone(),
                Some(_) => bounded_text::required(name, NAME_LENGTH, "A project name")?,
            };
            if let Some(target) = &target {
                if persistence::project_named(&mut tx, target.id, &new_name).await?.is_some() {
                    return Err(TargetError::conflict(
                        format!(
                            "The solution {} already holds a project named \"{new_name}\". Rename one of the two before \
                             moving.",
                            target.name
                        ),
                        PROJECT_NAME_TAKEN,
                    ));
                }
                row.solution_id = target.id;
            } else if name.is_some() {
                refuse_if_project_name_taken(&mut tx, previous_solution, &new_name, Some(id)).await?;
            }
            row.name = new_name;
            if description.is_some() {
                row.description = bounded_text::optional(description, DESCRIPTION_LENGTH, "The description")?;
            }
            persistence::update_project(&mut tx, &row).await?;
            let mut change = format!(
                "Project {previous} updated{}",
                if previous == row.name { String::new() } else { format!(" → {}", row.name) }
            );
            if let Some(target) = &target {
                let from = persistence::solution(&mut tx, previous_solution)
                    .await?
                    .map_or_else(|| naming::DELETED.to_owned(), |solution| solution.name);
                change.push_str(&format!(
                    "; moved from solution {from} to {} (its repositories, images, grants and checklists follow it)",
                    target.name
                ));
            }
            Ok::<_, TargetError>((row, change))
        }
        .await;
        let (row, change) = finish(tx, outcome).await?;
        self.audit.record(actor.entry(AuditOperation::ProjectUpdated, &id.to_string(), &change)).await;
        Ok(ProjectView::from(&row))
    }

    /// Deletes a project: its repositories and images return to no project, the grants naming it are revoked, and the
    /// modules above that keep rows naming it drop theirs (`ProjectDeleted`, stand-ins until they are ported) — all in
    /// one transaction.
    pub async fn delete_project(&self, id: i64, actor: &RequestActor) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let row = require_project(&mut tx, id).await?;
            let detached = persistence::detach_repositories(&mut tx, id).await?;
            let detached_images = persistence::detach_containers(&mut tx, id).await?;
            let revoked = vectispire_cp_access::target_grants::revoke_all(
                &mut tx,
                vectispire_cp_access::visibility::KIND_PROJECT,
                id,
            )
            .await
            .map_err(TargetError::unexpected)?;
            persistence::delete_project(&mut tx, id).await?;
            Ok::<_, TargetError>((row, detached, detached_images, revoked.grants))
        }
        .await;
        let (row, detached, detached_images, grants) = finish(tx, outcome).await?;
        let deleted = actor.entry(
            AuditOperation::ProjectUpdated,
            &id.to_string(),
            &format!(
                "Project deleted: {} ({detached} repository(ies) and {detached_images} image(s) returned to no \
                 project, {grants} grant(s) revoked)",
                row.name
            ),
        );
        self.audit.record(if grants > 0 { deleted.signalling(ACCESS_GRANT_CHANGED) } else { deleted }).await;
        Ok(())
    }

    pub async fn project(&self, id: i64) -> Result<Option<ProjectView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let found = persistence::project(&mut tx, id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(found.as_ref().map(ProjectView::from))
    }

    /// Labels for these projects, those that exist, a thousand per statement.
    pub async fn project_labels(&self, ids: &[i64]) -> Result<BTreeMap<i64, ProjectLabel>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let projects = persistence::projects_by_ids(&mut tx, ids).await?;
        let solution_ids: Vec<i64> = projects.iter().map(|project| project.solution_id).collect();
        let solutions: BTreeMap<i64, String> = persistence::solutions_by_ids(&mut tx, &solution_ids)
            .await?
            .into_iter()
            .map(|solution| (solution.id, solution.name))
            .collect();
        tx.commit().await.map_err(StoreError::from)?;
        Ok(projects
            .into_iter()
            .map(|project| {
                let label = ProjectLabel {
                    id: project.id,
                    solution_name: solutions.get(&project.solution_id).cloned(),
                    solution_id: project.solution_id,
                    name: project.name,
                };
                (label.id, label)
            })
            .collect())
    }

    // ── filing ───────────────────────────────────────────────────────────────────────────

    /// Files a repository into a project — or moves it, and visibility moves with it.
    pub async fn file_repository(
        &self,
        project_id: i64,
        repository_id: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let project = require_project(&mut tx, project_id).await?;
            let found = persistence::repository(&mut tx, repository_id).await?;
            let repository = rows::require_visible_repository(found, repository_id, allowed)?;
            if repository.project_id == Some(project_id) {
                return Ok(None);
            }
            persistence::assign_repository(&mut tx, repository_id, Some(project_id)).await?;
            let name = naming::of_repository(&repository);
            let description = match repository.project_id {
                None => format!(
                    "Repository {name} filed into project {}: holders of that project's grant now see it",
                    project.name
                ),
                Some(previous) => format!(
                    "Repository {name} moved from project {} to {}: visibility moves with it — holders of the first \
                     project's grant no longer see it through that grant, holders of the second now do",
                    project_name(&mut tx, previous).await?,
                    project.name
                ),
            };
            Ok::<_, TargetError>(Some(description))
        }
        .await;
        if let Some(description) = finish(tx, outcome).await? {
            self.audit
                .record(actor.entry(
                    AuditOperation::ProjectRepositoriesChanged,
                    &repository_id.to_string(),
                    &description,
                ))
                .await;
        }
        Ok(())
    }

    /// Returns a repository to no project; "This repository is not in that project." when it is in another.
    pub async fn remove_repository(
        &self,
        project_id: i64,
        repository_id: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let project = require_project(&mut tx, project_id).await?;
            let found = persistence::repository(&mut tx, repository_id).await?;
            let repository = rows::require_visible_repository(found, repository_id, allowed)?;
            if repository.project_id != Some(project_id) {
                return Err(TargetError::not_found("This repository is not in that project."));
            }
            persistence::assign_repository(&mut tx, repository_id, None).await?;
            Ok::<_, TargetError>(format!(
                "Repository {} removed from project {}: holders of that project's grant no longer see it through that \
                 grant",
                naming::of_repository(&repository),
                project.name
            ))
        }
        .await;
        let description = finish(tx, outcome).await?;
        self.audit
            .record(actor.entry(AuditOperation::ProjectRepositoriesChanged, &repository_id.to_string(), &description))
            .await;
        Ok(())
    }

    /// Files an image into a project, or moves it.
    pub async fn file_container(
        &self,
        project_id: i64,
        container_id: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let project = require_project(&mut tx, project_id).await?;
            let found = persistence::container(&mut tx, container_id).await?;
            let container = rows::require_visible_row(found, ScanTarget::Container(container_id), allowed)?;
            if container.project_id == Some(project_id) {
                return Ok(None);
            }
            persistence::assign_container(&mut tx, container_id, Some(project_id)).await?;
            let name = naming::of_container(&container);
            let description = match container.project_id {
                None => format!(
                    "Image {name} filed into project {}: holders of that project's grant now see it",
                    project.name
                ),
                Some(previous) => format!(
                    "Image {name} moved from project {} to {}: visibility moves with it — holders of the first \
                     project's grant no longer see it through that grant, holders of the second now do",
                    project_name(&mut tx, previous).await?,
                    project.name
                ),
            };
            Ok::<_, TargetError>(Some(description))
        }
        .await;
        if let Some(description) = finish(tx, outcome).await? {
            self.audit
                .record(actor.entry(AuditOperation::ProjectContainersChanged, &container_id.to_string(), &description))
                .await;
        }
        Ok(())
    }

    /// Returns an image to no project.
    pub async fn remove_container(
        &self,
        project_id: i64,
        container_id: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let project = require_project(&mut tx, project_id).await?;
            let found = persistence::container(&mut tx, container_id).await?;
            let container = rows::require_visible_row(found, ScanTarget::Container(container_id), allowed)?;
            if container.project_id != Some(project_id) {
                return Err(TargetError::not_found("This image is not in that project."));
            }
            persistence::assign_container(&mut tx, container_id, None).await?;
            Ok::<_, TargetError>(format!(
                "Image {} removed from project {}: holders of that project's grant no longer see it through that grant",
                naming::of_container(&container),
                project.name
            ))
        }
        .await;
        let description = finish(tx, outcome).await?;
        self.audit
            .record(actor.entry(AuditOperation::ProjectContainersChanged, &container_id.to_string(), &description))
            .await;
        Ok(())
    }

    pub(crate) async fn record_all(&self, entries: Vec<Record>) {
        for entry in entries {
            self.audit.record(entry).await;
        }
    }
}

/// Commits after `outcome` succeeded, rolls back otherwise — the transaction's end in one place.
pub(crate) async fn finish<T>(tx: Tx, outcome: Result<T, TargetError>) -> Result<T, TargetError> {
    match outcome {
        Ok(value) => {
            tx.commit().await.map_err(StoreError::from)?;
            Ok(value)
        }
        Err(refusal) => {
            let _ = tx.rollback().await;
            Err(refusal)
        }
    }
}

async fn require_solution(tx: &mut Tx, id: i64) -> Result<SolutionRow, TargetError> {
    persistence::solution(tx, id).await?.ok_or_else(|| TargetError::not_found(rows::SOLUTION_NOT_FOUND))
}

async fn require_project(tx: &mut Tx, id: i64) -> Result<ProjectRow, TargetError> {
    persistence::project(tx, id).await?.ok_or_else(|| TargetError::not_found(rows::PROJECT_NOT_FOUND))
}

async fn project_name(tx: &mut Tx, id: i64) -> Result<String, TargetError> {
    Ok(persistence::project(tx, id).await?.map_or_else(|| naming::DELETED.to_owned(), |project| project.name))
}

/// Refused here rather than left to the constraint, which answers a 500 carrying a driver's message — and which
/// folds case on MySQL and not on PostgreSQL.
async fn refuse_if_solution_name_taken(tx: &mut Tx, name: &str, this: Option<i64>) -> Result<(), TargetError> {
    match persistence::solution_named(tx, name).await? {
        Some(existing) if Some(existing.id) != this => {
            Err(TargetError::conflict(format!("A solution named \"{name}\" already exists."), SOLUTION_NAME_TAKEN))
        }
        _ => Ok(()),
    }
}

async fn refuse_if_project_name_taken(
    tx: &mut Tx,
    solution_id: i64,
    name: &str,
    this: Option<i64>,
) -> Result<(), TargetError> {
    match persistence::project_named(tx, solution_id, name).await? {
        Some(existing) if Some(existing.id) != this => Err(TargetError::conflict(
            format!("This solution already holds a project named \"{name}\"."),
            PROJECT_NAME_TAKEN,
        )),
        _ => Ok(()),
    }
}
