//! `RepositoryIdentityService`: every repository row given its identity and, where it is free, its guard (V73).
//!
//! **Why after the start, and every hour.** The identity is computed here, not in SQL, so the migration left both
//! columns null; until a row holds its guard, the routes' duplicate check cannot see it, and a second filing would be
//! accepted. So the rows are keyed by the hourly turn — every hour because an instance of the previous version, still
//! serving during a rolling upgrade, writes rows without one.
//!
//! **Oldest first, and nothing taken from anyone.** Of two rows already filing the same target, the older takes the
//! guard and the younger keeps none: both stay served and scanned, and the pair is listed as duplicates until an
//! administrator merges it. **Every instance runs it**: each write is conditional on the row still holding no guard
//! and still naming what was read, so two instances keying together write one value.

use vectispire_domain::repository_identity::RepositoryIdentity;

use crate::Targets;
use crate::error::TargetError;
use crate::persistence::{self, Keying, StoreError};

/// What one turn did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Keyed {
    /// Rows that took their guard.
    pub keyed: u32,
    /// Rows left without one because another row files the same target.
    pub twins: u32,
}

impl Targets {
    /// `keyUnkeyed`.
    pub async fn key_unkeyed(&self) -> Result<Keyed, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::unguarded_repositories(&mut tx).await?;
        tx.commit().await.map_err(StoreError::from)?;
        let mut done = Keyed::default();
        for row in rows {
            let Some(target) = RepositoryIdentity::of(&row.url, Some(&row.branch), row.sub_path.as_deref()) else {
                // A URL that names no host — a row older than the URL's validation. Nothing to compare.
                continue;
            };
            let guard = target.guard();
            // Each row in a transaction of its own: a write refused because a creation took the guard in between
            // leaves the row for the next turn, and the turn goes on.
            let outcome = async {
                let mut tx = persistence::write(&self.db).await?;
                let free = persistence::repository_by_guard(&mut tx, &guard).await?.is_none();
                if !free && row.url_identity.as_deref() == Some(target.repository.as_str()) {
                    tx.commit().await.map_err(StoreError::from)?;
                    return Ok::<_, StoreError>(Some(false));
                }
                let written = persistence::key_repository(
                    &mut tx,
                    &Keying {
                        id: row.id,
                        url: &row.url,
                        branch: &row.branch,
                        sub_path: row.sub_path.as_deref().unwrap_or(""),
                        url_identity: &target.repository,
                        guard: free.then_some(guard.as_str()),
                    },
                )
                .await;
                match written {
                    Ok(1) => {
                        tx.commit().await.map_err(StoreError::from)?;
                        Ok(Some(free))
                    }
                    Ok(_) => {
                        tx.commit().await.map_err(StoreError::from)?;
                        Ok(None)
                    }
                    Err(refused) => {
                        let _ = tx.rollback().await;
                        Err(refused)
                    }
                }
            }
            .await;
            match outcome {
                Ok(Some(true)) => done.keyed = done.keyed.saturating_add(1),
                Ok(Some(false)) => done.twins = done.twins.saturating_add(1),
                Ok(None) => {}
                Err(refused) => {
                    tracing::debug!(repository = row.id, error = %refused, "Repository was not keyed this turn");
                }
            }
        }
        if done.keyed > 0 {
            tracing::info!(keyed = done.keyed, "repository target(s) received their identity");
        }
        Ok(done)
    }
}
