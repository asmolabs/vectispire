//! `QualityQueryService`: the quality screen's counts — open quality findings, distinct rules and files, the top
//! rules, files and repositories — within what the caller may see. Quality never blocks the gate (decision 0005).

use std::sync::Arc;

use serde::Serialize;
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_issues::queries::Axis;
use vectispire_cp_issues::{IssueCatalog, IssueFilters};
use vectispire_cp_targets::naming::{self, DELETED};

use crate::error::PostureError;

const TOP: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bucket {
    pub label: Option<String>,
    pub count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityOverview {
    pub open_count: i64,
    pub rule_count: i64,
    pub file_count: i64,
    pub top_rules: Vec<Bucket>,
    pub top_files: Vec<Bucket>,
    pub top_targets: Vec<Bucket>,
}

#[derive(Clone)]
pub struct Quality {
    db: Db,
    issues: Arc<IssueCatalog>,
}

opaque_debug!(Quality);

impl Quality {
    pub fn new(db: Db, issues: Arc<IssueCatalog>) -> Quality {
        Quality { db, issues }
    }

    pub async fn overview(&self, allowed: &Visibility) -> Result<QualityOverview, PostureError> {
        let mut filters = IssueFilters {
            state: Some("open".to_owned()),
            type_: Some("quality".to_owned()),
            ..IssueFilters::new(Visibility::Everything)
        };
        if let Visibility::Only(targets) = allowed {
            let repositories: Vec<ScanTarget> =
                targets.iter().copied().filter(|target| matches!(target, ScanTarget::Repository(_))).collect();
            // An allowance holding no repository is answered without a query; falling back to the unrestricted form
            // here would be the inversion `Visibility` exists to prevent.
            if repositories.is_empty() {
                return Ok(QualityOverview {
                    open_count: 0,
                    rule_count: 0,
                    file_count: 0,
                    top_rules: Vec::new(),
                    top_files: Vec::new(),
                    top_targets: Vec::new(),
                });
            }
            filters = filters.within(repositories);
        }
        let buckets = |rows: Vec<(Option<String>, i64)>| {
            rows.into_iter().map(|(label, count)| Bucket { label, count }).collect::<Vec<_>>()
        };
        let top_rules =
            buckets(self.issues.count_grouped(&filters, Axis::Rule, TOP).await.map_err(PostureError::unexpected)?);
        let top_files =
            buckets(self.issues.count_grouped(&filters, Axis::File, TOP).await.map_err(PostureError::unexpected)?);
        let by_repository =
            self.issues.count_grouped_by_repository(&filters, TOP).await.map_err(PostureError::unexpected)?;
        let names = naming::all(&self.db).await.map_err(PostureError::unexpected)?;
        let top_targets = by_repository
            .into_iter()
            .map(|(repository, count)| Bucket {
                label: Some(names.repositories.get(&repository).cloned().unwrap_or_else(|| DELETED.to_owned())),
                count,
            })
            .collect();
        Ok(QualityOverview {
            open_count: self.issues.count(&filters).await.map_err(PostureError::unexpected)?,
            rule_count: self.issues.count_distinct(&filters, Axis::Rule).await.map_err(PostureError::unexpected)?,
            file_count: self.issues.count_distinct(&filters, Axis::File).await.map_err(PostureError::unexpected)?,
            top_rules,
            top_files,
            top_targets,
        })
    }
}
