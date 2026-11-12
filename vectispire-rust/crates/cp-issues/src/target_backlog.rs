//! Implementation of `vectispire_cp_targets::TargetBacklog`.

use std::collections::BTreeMap;

use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::TargetBacklog;
use vectispire_cp_targets::ports::{OpenBySeverity, PortError};
use vectispire_domain::Severity;

use crate::persistence::IssueRepository;

/// `TargetBacklogFigures`: the open issue figures for targets listings and solution tree.
pub struct TargetBacklogFigures {
    db: Db,
}

impl TargetBacklogFigures {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

impl TargetBacklog for TargetBacklogFigures {
    fn open_per_repository(&self) -> BoxFuture<'_, Result<BTreeMap<i64, i64>, PortError>> {
        Box::pin(async move {
            let mut tx = crate::persistence::read(&self.db).await?;
            let pairs = IssueRepository::count_open_by_repository(&mut tx, "open")
                .await
                .map_err(|e| PortError::from(Box::new(e) as Box<dyn std::error::Error + Send + Sync>))?;
            Ok(pairs.into_iter().collect())
        })
    }

    fn open_per_container(&self) -> BoxFuture<'_, Result<BTreeMap<i64, i64>, PortError>> {
        Box::pin(async move {
            let mut tx = crate::persistence::read(&self.db).await?;
            let pairs = IssueRepository::count_open_by_container(&mut tx, "open")
                .await
                .map_err(|e| PortError::from(Box::new(e) as Box<dyn std::error::Error + Send + Sync>))?;
            Ok(pairs.into_iter().collect())
        })
    }

    fn open_by_severity_per_target<'a>(
        &'a self,
        narrowed: &'a Visibility,
    ) -> BoxFuture<'a, Result<OpenBySeverity, PortError>> {
        Box::pin(async move {
            let mut tx = crate::persistence::read(&self.db).await?;
            let rows = IssueRepository::count_open_by_target_and_severity(&mut tx, narrowed)
                .await
                .map_err(|e| PortError::from(Box::new(e) as Box<dyn std::error::Error + Send + Sync>))?;

            let mut result: OpenBySeverity = BTreeMap::new();
            for (repo_id, container_id, severity_str, count) in rows {
                let target = match (repo_id, container_id) {
                    (Some(id), _) => ScanTarget::Repository(id),
                    (None, Some(id)) => ScanTarget::Container(id),
                    (None, None) => continue,
                };
                let severity = Severity::of(Some(severity_str.as_str()));
                result.entry(target).or_default().insert(severity, count);
            }
            Ok(result)
        })
    }
}

opaque_debug!(TargetBacklogFigures);
