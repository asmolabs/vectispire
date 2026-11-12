//! The module's implementation behind its API: its two maintenance tasks, and the ports `access` declares that
//! `targets` answers — `GrantableTargets` and `IssuerSees`.

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_access::accounts::AccountStore;
use vectispire_cp_access::credentials::IssuerSees;
use vectispire_cp_access::visibility::Grant;
use vectispire_cp_access::{AccessError, AccountRef, GrantableTargets, Labels, TargetGrant, VisibilityService};
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};
use vectispire_domain::team_rules::{KIND_CONTAINER, KIND_PROJECT, KIND_REPOSITORY};

use crate::Targets;
use crate::naming;
use crate::persistence::{self, StoreError};

/// `RepositoryIdentityTask`: the rows without their identity keyed — those V73 found, and those an instance of the
/// previous version writes during a rolling upgrade. Until a row is keyed, a second filing of its target is accepted.
#[derive(Debug)]
pub struct RepositoryIdentityTask(pub Arc<Targets>);

impl MaintenanceTask for RepositoryIdentityTask {
    fn sequence(&self) -> Sequence {
        Sequence::RepositoryIdentities
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            self.0.key_unkeyed().await?;
            Ok(())
        })
    }
}

/// `OrphanedTargetRowsTask`: the rows a deleted target left behind, swept — last, after every task that could still
/// name them.
#[derive(Debug)]
pub struct OrphanedTargetRowsTask(pub Arc<Targets>);

impl MaintenanceTask for OrphanedTargetRowsTask {
    fn sequence(&self) -> Sequence {
        Sequence::OrphanedTargetRows
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            self.0.purge_orphans().await?;
            Ok(())
        })
    }
}

/// `TargetsForAccess`: `access`' `GrantableTargets`, answered from the rows this module owns.
#[derive(Debug, Clone)]
pub struct TargetsForAccess(pub vectispire_cp_db::Db);

impl GrantableTargets for TargetsForAccess {
    /// Repositories first, then images, a thousand projects per statement.
    fn targets_in<'a>(&'a self, projects: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<Vec<ScanTarget>, AccessError>> {
        Box::pin(async move {
            let ids: Vec<i64> = projects.iter().copied().collect();
            let found = async {
                let mut tx = persistence::read(&self.0).await?;
                let repositories = persistence::repository_ids_in_projects(&mut tx, &ids).await?;
                let containers = persistence::container_ids_in_projects(&mut tx, &ids).await?;
                tx.commit().await.map_err(StoreError::from)?;
                Ok::<_, StoreError>((repositories, containers))
            }
            .await;
            let (repositories, containers) = found.map_err(port)?;
            Ok(repositories
                .into_iter()
                .map(ScanTarget::Repository)
                .chain(containers.into_iter().map(ScanTarget::Container))
                .collect())
        })
    }

    /// `TargetNaming.named`: the repositories and images in one pass, the projects as `Solution / Project`.
    fn named<'a>(&'a self, grants: &'a [Grant]) -> BoxFuture<'a, Result<Vec<TargetGrant>, AccessError>> {
        Box::pin(async move {
            let ids = |kind: &str| -> BTreeSet<i64> {
                grants.iter().filter(|grant| grant.kind == kind).map(|grant| grant.id).collect()
            };
            let names = naming::for_ids(&self.0, &ids(KIND_REPOSITORY), &ids(KIND_CONTAINER)).await.map_err(port)?;
            let projects = async {
                let mut tx = persistence::read(&self.0).await?;
                let named = naming::project_names(&mut tx, &ids(KIND_PROJECT)).await?;
                tx.commit().await.map_err(StoreError::from)?;
                Ok::<_, StoreError>(named)
            }
            .await
            .map_err(port)?;
            Ok(grants
                .iter()
                .map(|grant| TargetGrant {
                    kind: grant.kind.clone(),
                    id: grant.id,
                    name: match grant.kind.as_str() {
                        KIND_REPOSITORY => names.of(Some(grant.id), None),
                        KIND_CONTAINER => names.of(None, Some(grant.id)),
                        KIND_PROJECT => projects.get(&grant.id).cloned().unwrap_or_else(|| naming::DELETED.to_owned()),
                        _ => naming::DELETED.to_owned(),
                    },
                })
                .collect())
        })
    }

    fn project_exists(&self, project_id: i64) -> BoxFuture<'_, Result<bool, AccessError>> {
        Box::pin(async move {
            let found = async {
                let mut tx = persistence::read(&self.0).await?;
                let project = persistence::project(&mut tx, project_id).await?;
                tx.commit().await.map_err(StoreError::from)?;
                Ok::<_, StoreError>(project.is_some())
            }
            .await;
            found.map_err(port)
        })
    }

    fn exists(&self, target: ScanTarget) -> BoxFuture<'_, Result<bool, AccessError>> {
        Box::pin(async move {
            let found = async {
                let mut tx = persistence::read(&self.0).await?;
                let exists = match target {
                    ScanTarget::Repository(id) => persistence::repository(&mut tx, id).await?.is_some(),
                    ScanTarget::Container(id) => persistence::container(&mut tx, id).await?.is_some(),
                };
                tx.commit().await.map_err(StoreError::from)?;
                Ok::<_, StoreError>(exists)
            }
            .await;
            found.map_err(port)
        })
    }

    /// Every target's name, by identifier — the creation order.
    fn labels(&self) -> BoxFuture<'_, Result<Labels, AccessError>> {
        Box::pin(async move {
            let names = naming::all(&self.0).await.map_err(port)?;
            Ok(Labels {
                repositories: names.repositories.into_iter().collect(),
                containers: names.containers.into_iter().collect(),
            })
        })
    }
}

/// A store failure behind the port, in the port's error: answered as the failure it is, never as "absent".
fn port(failure: StoreError) -> AccessError {
    AccessError::Port(failure.to_string())
}

/// `requireIssuerSees`: whether a key's issuer may restrict it to a target — the target exists, and the issuer's
/// account sees it (`VisibilityService.of(owner)`, the account alone, no credential narrowing it).
pub struct IssuerSeesTargets<A> {
    pub targets: Arc<Targets>,
    pub visibility: VisibilityService,
    pub accounts: A,
}

impl<A> std::fmt::Debug for IssuerSeesTargets<A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("IssuerSeesTargets").finish_non_exhaustive()
    }
}

/// A failure behind the port, in the port's error type.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct PortFailure(String);

impl<A: AccountStore + Send + Sync> IssuerSees for IssuerSeesTargets<A> {
    fn issuer_sees<'a>(
        &'a self,
        issuer: i64,
        target: ScanTarget,
    ) -> BoxFuture<'a, Result<bool, vectispire_cp_access::credentials::StoreError>> {
        Box::pin(async move {
            let failed = |message: String| {
                vectispire_cp_access::credentials::StoreError::from_port(Box::new(PortFailure(message)))
            };
            if !self.targets.target_exists(target).await.map_err(|error| failed(error.to_string()))? {
                return Ok(false);
            }
            let Some(owner) = self.accounts.find_by_id(issuer).await.map_err(|error| failed(error.to_string()))? else {
                return Ok(false);
            };
            let account = AccountRef { id: issuer, role: owner.role.clone() };
            let visibility = self
                .visibility
                .of(Some(&account), &Visibility::Everything)
                .await
                .map_err(|error| failed(error.to_string()))?;
            Ok(visibility.permits(target))
        })
    }
}
