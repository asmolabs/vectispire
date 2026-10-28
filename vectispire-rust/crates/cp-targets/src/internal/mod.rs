//! The module's implementation behind its API: its two maintenance tasks, and the ports `access` declares that
//! `targets` answers — `GrantableTargets` and `IssuerSees`.

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_access::accounts::AccountStore;
use vectispire_cp_access::credentials::IssuerSees;
use vectispire_cp_access::{AccessError, AccountRef, GrantableTargets, VisibilityService};
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};

use crate::Targets;
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
            let (repositories, containers) = found.map_err(|failure| AccessError::Port(failure.to_string()))?;
            Ok(repositories
                .into_iter()
                .map(ScanTarget::Repository)
                .chain(containers.into_iter().map(ScanTarget::Container))
                .collect())
        })
    }
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
