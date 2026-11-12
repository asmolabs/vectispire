//! Putting a scan in the queue on somebody's request — `ScanTriggerService`.
//!
//! **Queueing, not running**: the call returns at once and a worker, built-in or remote, claims the row. And **one
//! place builds a scan row** besides the scheduler's, so neither can forget the required label: a scan keeps the
//! requirement that held when it was asked for, even if the target's label changes afterwards.

use time::OffsetDateTime;
use vectispire_cp_targets::views::{ContainerView, RepositoryView};

use crate::catalog::ScanCatalog;
use crate::persistence::{self, NewScan, StoreError};

/// `AlreadyQueuedException`'s sentence: refused rather than stacked — ten clicks would give ten identical scans, nine
/// pointless, the tenth reporting on a tree that has not changed since the first.
pub const ALREADY_QUEUED: &str = "A scan of this target is already queued.";

/// "n/a", what an image scan's mandatory branch holds — the trigger's and the scheduler's alike, so a scheduled scan
/// and a manual one are indistinguishable downstream.
pub const IMAGE_BRANCH: &str = "n/a";

/// A scan queued, or why not.
#[derive(Debug, thiserror::Error)]
pub enum TriggerError {
    #[error("{0}")]
    AlreadyQueued(&'static str),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl ScanCatalog {
    /// `trigger(repository, notBefore)`: queued, and claimed by no executor before `not_before` — the column a failed
    /// attempt's wait uses, which every selection and the take already honour. `None` claims at once.
    pub async fn trigger_repository(
        &self,
        repository: &RepositoryView,
        not_before: Option<OffsetDateTime>,
    ) -> Result<i64, TriggerError> {
        let scan = NewScan {
            status: "pending".to_owned(),
            created_at: self.clock.now(),
            repo_id: Some(repository.id),
            container_id: None,
            branch: repository.branch.clone(),
            sub_path: repository.sub_path.clone(),
            required_agent_label: repository.required_agent_label.clone(),
            not_before,
        };
        let mut tx = persistence::write(&self.db).await?;
        let queued = async {
            if persistence::count_of_repository(&mut tx, "pending", repository.id).await? > 0 {
                return Err(TriggerError::AlreadyQueued(ALREADY_QUEUED));
            }
            Ok(persistence::insert_scan(&mut tx, &scan).await?)
        }
        .await;
        settle(tx, queued).await
    }

    /// `trigger(container)`.
    pub async fn trigger_container(&self, container: &ContainerView) -> Result<i64, TriggerError> {
        let scan = NewScan {
            status: "pending".to_owned(),
            created_at: self.clock.now(),
            repo_id: None,
            container_id: Some(container.id),
            branch: IMAGE_BRANCH.to_owned(),
            sub_path: None,
            required_agent_label: container.required_agent_label.clone(),
            not_before: None,
        };
        let mut tx = persistence::write(&self.db).await?;
        let queued = async {
            if persistence::count_of_container(&mut tx, "pending", container.id).await? > 0 {
                return Err(TriggerError::AlreadyQueued(ALREADY_QUEUED));
            }
            Ok(persistence::insert_scan(&mut tx, &scan).await?)
        }
        .await;
        settle(tx, queued).await
    }
}

async fn settle<T>(tx: vectispire_cp_db::Tx, done: Result<T, TriggerError>) -> Result<T, TriggerError> {
    match done {
        Ok(value) => {
            tx.commit().await.map_err(StoreError::from)?;
            Ok(value)
        }
        Err(refused) => {
            let _ = tx.rollback().await;
            Err(refused)
        }
    }
}
