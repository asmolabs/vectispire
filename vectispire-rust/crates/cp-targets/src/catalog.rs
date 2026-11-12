//! `TargetCatalog`: the repositories and images as the other modules read them — views, never rows. The module that
//! owns the rows is the only one that sees them (decision 0029). Visibility stays the caller's to apply, as it was.
//!
//! **Three writes, each one column another module decides**: whether a target is in the certified scope
//! (`compliance`), a repository's badge token (`posture`), and when the scheduler last considered a target
//! (`scanning`). The columns live on the target's row and are written here, by the owner, on the decider's behalf.

use std::collections::BTreeSet;

use time::OffsetDateTime;
use vectispire_cp_db::{ScanTarget, Tx};

use crate::Targets;
use crate::error::TargetError;
use crate::persistence::{self, StoreError};
use crate::views::{ContainerView, RepositoryView};

/// A repository's published badge token — a bearer capability, so never in [`RepositoryView`].
#[derive(Clone, PartialEq, Eq)]
pub struct BadgeToken {
    pub repository_id: i64,
    pub token: Option<String>,
}

impl std::fmt::Debug for BadgeToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("BadgeToken").field("repository_id", &self.repository_id).finish_non_exhaustive()
    }
}

/// What putting a target in or out of the certified scope did. **Three outcomes, not a boolean**: a `false` used to
/// mean both "already so" and "no such target", and the route answered 200 for an id nobody had registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeChange {
    Changed,
    Unchanged,
    Absent,
}

impl Targets {
    /// Every repository, by identifier.
    pub async fn catalog_repositories(&self) -> Result<Vec<RepositoryView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::repositories(&mut tx).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(rows.iter().map(RepositoryView::from).collect())
    }

    /// Every image, by identifier.
    pub async fn catalog_containers(&self) -> Result<Vec<ContainerView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::containers(&mut tx).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(rows.iter().map(ContainerView::from).collect())
    }

    pub async fn catalog_repository(&self, id: i64) -> Result<Option<RepositoryView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = persistence::repository(&mut tx, id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(row.as_ref().map(RepositoryView::from))
    }

    pub async fn catalog_container(&self, id: i64) -> Result<Option<ContainerView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = persistence::container(&mut tx, id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(row.as_ref().map(ContainerView::from))
    }

    /// The repositories with these identifiers that exist, a thousand per statement — a reader's allowance can be
    /// larger than any engine's parameter ceiling.
    pub async fn catalog_repositories_by_ids(&self, ids: &BTreeSet<i64>) -> Result<Vec<RepositoryView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::repositories_by_ids(&mut tx, &ids.iter().copied().collect::<Vec<_>>()).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(rows.iter().map(RepositoryView::from).collect())
    }

    pub async fn catalog_containers_by_ids(&self, ids: &BTreeSet<i64>) -> Result<Vec<ContainerView>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::containers_by_ids(&mut tx, &ids.iter().copied().collect::<Vec<_>>()).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(rows.iter().map(ContainerView::from).collect())
    }

    /// Those of these repositories cloned with a credential of their own — the two columns the dispatcher reads to
    /// decide what to send, and nothing more.
    pub async fn carrying_credentials(&self, ids: &BTreeSet<i64>) -> Result<BTreeSet<i64>, TargetError> {
        Ok(self
            .catalog_repositories_by_ids(ids)
            .await?
            .into_iter()
            .filter(|repository| repository.ssh_key_id.is_some() || repository.https_token_id.is_some())
            .map(|repository| repository.id)
            .collect())
    }

    pub async fn target_exists(&self, target: ScanTarget) -> Result<bool, TargetError> {
        Ok(match target {
            ScanTarget::Repository(id) => self.catalog_repository(id).await?.is_some(),
            ScanTarget::Container(id) => self.catalog_container(id).await?.is_some(),
        })
    }

    /// `stampScheduled`, in the scheduler's transaction: a targeted update, never a save of a row read at the top of
    /// the tick, which would write back what an operator changed in between.
    pub async fn stamp_scheduled(
        &self,
        tx: &mut Tx,
        target: ScanTarget,
        at: OffsetDateTime,
    ) -> Result<(), TargetError> {
        match target {
            ScanTarget::Repository(id) => persistence::stamp_repository(tx, id, at).await?,
            ScanTarget::Container(id) => persistence::stamp_container(tx, id, at).await?,
        };
        Ok(())
    }

    /// `None` when the repository does not exist.
    pub async fn badge_token(&self, repository_id: i64) -> Result<Option<BadgeToken>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = persistence::repository(&mut tx, repository_id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(row.map(|row| BadgeToken { repository_id: row.id, token: row.badge_token }))
    }

    /// The repository published under this token, or `None` for a token nobody holds.
    pub async fn repository_with_badge(&self, token: &str) -> Result<Option<i64>, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = persistence::repository_by_badge(&mut tx, token).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(row.map(|row| row.id))
    }

    /// Stores the token `posture` generated, or clears it with `None`.
    pub async fn set_badge_token(&self, repository_id: i64, token: Option<&str>) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        if let Some(mut row) = persistence::repository(&mut tx, repository_id).await? {
            row.badge_token = token.map(str::to_owned);
            persistence::update_repository(&mut tx, &row).await?;
        }
        tx.commit().await.map_err(StoreError::from)?;
        Ok(())
    }

    /// Puts one target in or out of the certified scope — `compliance`'s decision, on the target's row.
    pub async fn set_in_certified_scope(&self, target: ScanTarget, in_scope: bool) -> Result<ScopeChange, TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let change = match target {
            ScanTarget::Repository(id) => match persistence::repository(&mut tx, id).await? {
                Some(mut row) => {
                    let changed = row.in_certified_scope != in_scope;
                    row.in_certified_scope = in_scope;
                    persistence::update_repository(&mut tx, &row).await?;
                    if changed { ScopeChange::Changed } else { ScopeChange::Unchanged }
                }
                None => ScopeChange::Absent,
            },
            ScanTarget::Container(id) => match persistence::container(&mut tx, id).await? {
                Some(mut row) => {
                    let changed = row.in_certified_scope != in_scope;
                    row.in_certified_scope = in_scope;
                    persistence::update_container(&mut tx, &row).await?;
                    if changed { ScopeChange::Changed } else { ScopeChange::Unchanged }
                }
                None => ScopeChange::Absent,
            },
        };
        tx.commit().await.map_err(StoreError::from)?;
        Ok(change)
    }
}
