//! `TargetImports`: what decision 0037's import from a forge asks of the targets' owner — which repositories are
//! already targets, which solutions and projects exist by name, how far a project's grants reach — and the creations
//! themselves, many in one transaction (task 2.6 ports it for `forges`, Phase 4).
//!
//! **The existing gestures, in a loop**: a target is created with the form's refusals and entry, a solution and a
//! project likewise. An import is not a second way to create a target.
//!
//! **One transaction, and the entries after it.** An import creates everything or nothing; the entries are collected
//! while the batch runs and recorded once it has committed — of a batch that rolled back, none is recorded. A batch
//! dropped without [`ImportBatch::commit`] rolls back.

use std::collections::{BTreeMap, BTreeSet};

use time::OffsetDateTime;
use vectispire_cp_access::VisibilityMode;
use vectispire_cp_access::target_grants::{self, Grantees};
use vectispire_cp_audit::{Record, RequestActor};
use vectispire_cp_db::{Tx, Visibility};
use vectispire_domain::repository_url;

use crate::Targets;
use crate::error::TargetError;
use crate::persistence::{self, StoreError};
use crate::ports::Queued;
use crate::repositories::{self, Changes, Filing};
use crate::views::{ProjectView, RepositoryView, SolutionView};

/// A solution or project an import files into, and whether the import created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed<T> {
    pub view: T,
    pub created: bool,
}

impl Targets {
    /// The targets filing each of these repositories, whatever their branch and sub-path — the identity rule the
    /// duplicate refusal uses — from the stored identity, and for the rows the keying has not reached from their URL,
    /// so a target added by an instance of the previous version is found all the same.
    pub async fn present_by_identity(&self, identities: &[String]) -> Result<BTreeMap<String, Vec<i64>>, TargetError> {
        let wanted: Vec<String> = identities.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
        let mut tx = persistence::read(&self.db).await?;
        let stored = persistence::repositories_by_identity(&mut tx, &wanted).await?;
        let unidentified = persistence::unidentified_repositories(&mut tx).await?;
        tx.commit().await.map_err(StoreError::from)?;
        let mut present: BTreeMap<String, Vec<i64>> = BTreeMap::new();
        for (id, identity) in stored {
            present.entry(identity).or_default().push(id);
        }
        for (id, url) in unidentified {
            if let Some(identity) = repository_url::identity(&url).filter(|identity| wanted.contains(identity)) {
                present.entry(identity).or_default().push(id);
            }
        }
        for ids in present.values_mut() {
            ids.sort_unstable();
        }
        Ok(present)
    }

    /// The reach of each of these projects that some grant names; a project missing from the answer has none.
    pub async fn grantees(&self, projects: &BTreeSet<i64>) -> Result<BTreeMap<i64, Grantees>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let reach = target_grants::grantees_of_projects(&mut tx, projects).await.map_err(TargetError::unexpected)?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(reach)
    }

    /// Whether every signed-in account sees every target, or only what it was granted.
    pub async fn visibility_mode(&self) -> Result<VisibilityMode, TargetError> {
        match &self.visibility {
            Some(service) => service.mode().await.map_err(TargetError::unexpected),
            None => Err(TargetError::unexpected(NoVisibility)),
        }
    }

    /// A batch of creations in one transaction, attributed to `actor`.
    pub async fn import_batch<'a>(&'a self, actor: &'a RequestActor) -> Result<ImportBatch<'a>, TargetError> {
        Ok(ImportBatch { targets: self, actor, tx: persistence::write(&self.db).await?, entries: Vec::new() })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("no visibility service was composed")]
struct NoVisibility;

/// The creations an import makes, inside one transaction.
#[derive(Debug)]
pub struct ImportBatch<'a> {
    targets: &'a Targets,
    actor: &'a RequestActor,
    tx: Tx,
    entries: Vec<Record>,
}

impl ImportBatch<'_> {
    /// The solution of that name, created when none exists — reused, never renamed.
    pub async fn solution(&mut self, name: &str) -> Result<Placed<SolutionView>, TargetError> {
        if let Some(existing) = persistence::solution_named(&mut self.tx, name).await? {
            return Ok(Placed { view: SolutionView::from(&existing), created: false });
        }
        let view =
            self.targets.create_solution_in(&mut self.tx, Some(name), None, self.actor, &mut self.entries).await?;
        Ok(Placed { view, created: true })
    }

    /// The project of that name in the solution, created when none exists — reused, never moved.
    pub async fn project(&mut self, solution_id: i64, name: &str) -> Result<Placed<ProjectView>, TargetError> {
        if let Some(existing) = persistence::project_named(&mut self.tx, solution_id, name).await? {
            return Ok(Placed { view: ProjectView::from(&existing), created: false });
        }
        let view = self
            .targets
            .create_project_in(&mut self.tx, solution_id, Some(name), None, self.actor, &mut self.entries)
            .await?;
        Ok(Placed { view, created: true })
    }

    /// A repository target, as the form creates it, filed into `project_id` at its creation. `scheduled_from` is
    /// stamped as its last scheduled round, so the default schedule first takes it at its own slot rather than at the
    /// next tick — a thousand targets imported in one gesture would otherwise all be scanned in the next minute.
    pub async fn repository(
        &mut self,
        changes: &Changes,
        project_id: Option<i64>,
        scheduled_from: OffsetDateTime,
        provenance: &str,
    ) -> Result<RepositoryView, TargetError> {
        let mut row = self.targets.built(changes).await?;
        row.last_scheduled_scan_at = Some(scheduled_from);
        match self.targets.file_in(&mut self.tx, &mut row, &Visibility::Everything).await {
            Ok(()) => {}
            Err(Filing::Refused(refusal)) => return Err(refusal),
            Err(Filing::Failed(failure)) => return Err(TargetError::from(failure)),
        }
        if let Some(project) = project_id {
            persistence::assign_repository(&mut self.tx, row.id, Some(project)).await?;
            row.project_id = Some(project);
        }
        self.entries.push(repositories::added(self.actor, &row, provenance));
        Ok(RepositoryView::from(&row))
    }

    /// Its first scan, claimed by no executor before `not_before`.
    pub async fn first_scan(
        &self,
        repository: &RepositoryView,
        not_before: OffsetDateTime,
    ) -> Result<Queued, TargetError> {
        self.targets.scans.queue_repository(repository, Some(not_before)).await.map_err(|error| match error {
            crate::ports::QueueError::AlreadyQueued(message) => {
                TargetError::Conflict { message, cause: None, members: Vec::new() }
            }
            crate::ports::QueueError::Failed(failure) => TargetError::Unexpected(failure),
        })
    }

    /// Commits, then records every entry the batch collected.
    pub async fn commit(self) -> Result<(), TargetError> {
        self.tx.commit().await.map_err(StoreError::from)?;
        self.targets.record_all(self.entries).await;
        Ok(())
    }
}
