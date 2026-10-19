//! Querying component inventory across the estate within visibility allowances.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use time::OffsetDateTime;
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_scanning::ScanCatalog;

use crate::component::ComponentOrigin;
use crate::persistence::{InventoryRepository, StoreError};

pub const MAX_ROWS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Occurrence {
    pub component: String,
    #[serde(rename = "componentVersion")]
    pub component_version: Option<String>,
    pub purl: Option<String>,
    pub r#type: Option<String>,
    pub direct: Option<bool>,
    #[serde(rename = "targetKind")]
    pub target_kind: String,
    #[serde(rename = "targetId")]
    pub target_id: Option<i64>,
    #[serde(rename = "targetName")]
    pub target_name: String,
    pub branch: Option<String>,
    #[serde(rename = "projectVersion")]
    pub project_version: Option<String>,
    #[serde(rename = "scanId")]
    pub scan_id: i64,
    #[serde(rename = "scannedAt", with = "time::serde::iso8601::option")]
    pub scanned_at: Option<OffsetDateTime>,
    pub source: String,
    #[serde(rename = "scannerVersion")]
    pub scanner_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchResults {
    pub occurrences: Vec<Occurrence>,
    pub total: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct InventoryQueryService {
    db: Db,
    scans: Arc<ScanCatalog>,
}

impl InventoryQueryService {
    pub fn new(db: Db, scans: Arc<ScanCatalog>) -> Self {
        Self { db, scans }
    }

    pub async fn search(
        &self,
        name: &str,
        version: Option<&str>,
        allowed: &Visibility,
    ) -> Result<SearchResults, StoreError> {
        let wanted = name.trim();
        if wanted.is_empty() {
            return Err(StoreError::Message("A component name is required.".to_owned()));
        }

        let name_like = format!("%{}%", wanted.to_ascii_lowercase());
        let version_clean = version.map(|v| v.trim()).filter(|v| !v.is_empty());

        let rows =
            InventoryRepository::search_components(&self.db, &name_like, version_clean, (MAX_ROWS + 1) as i64).await?;

        let names =
            vectispire_cp_targets::naming::all(&self.db).await.map_err(|e| StoreError::Message(e.to_string()))?;

        let mut visible = Vec::new();
        for r in rows {
            let target = match (r.repo_id, r.container_id) {
                (Some(id), _) => Some(ScanTarget::Repository(id)),
                (None, Some(id)) => Some(ScanTarget::Container(id)),
                _ => None,
            };
            if let Some(t) = target
                && allowed.permits(t)
            {
                visible.push(r);
            }
        }

        let scan_ids: Vec<i64> = visible.iter().map(|r| r.scan_id).collect();
        let labels = self.scans.labels_of(&scan_ids).await.map_err(|e| StoreError::Other(e.to_string()))?;

        let mut occurrences = Vec::new();
        for r in visible {
            let label = match labels.get(&r.scan_id) {
                Some(l) => l,
                None => continue,
            };

            let is_repo = r.repo_id.is_some();
            let target_kind = if is_repo { "repository" } else { "container" };
            let target_id = if is_repo { r.repo_id } else { r.container_id };
            let target_name = names.of(r.repo_id, r.container_id);

            let origin = ComponentOrigin::of_stored(r.origin.as_deref());
            let scanner_version = if origin == ComponentOrigin::Both { r.scanned_version.clone() } else { None };

            occurrences.push(Occurrence {
                component: r.name,
                component_version: r.version,
                purl: r.purl,
                r#type: r.type_,
                direct: r.is_direct,
                target_kind: target_kind.to_owned(),
                target_id,
                target_name,
                branch: Some(label.branch.clone()),
                project_version: label.version.clone(),
                scan_id: r.scan_id,
                scanned_at: r.scan_created_at,
                source: origin.wire_name().to_owned(),
                scanner_version,
            });
        }

        let truncated = occurrences.len() > MAX_ROWS;
        let occurrences_final = if truncated { occurrences.into_iter().take(MAX_ROWS).collect() } else { occurrences };
        let total = occurrences_final.len();

        Ok(SearchResults { occurrences: occurrences_final, total, truncated })
    }

    pub async fn versions(&self, name: &str, allowed: &Visibility) -> Result<Vec<String>, StoreError> {
        let wanted = name.trim();
        if wanted.is_empty() {
            return Ok(Vec::new());
        }

        let name_like = format!("%{}%", wanted.to_ascii_lowercase());
        let rows = InventoryRepository::versions_of(&self.db, &name_like, MAX_ROWS as i64).await?;

        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for (version, repo_id, container_id) in rows {
            let target = match (repo_id, container_id) {
                (Some(id), _) => Some(ScanTarget::Repository(id)),
                (None, Some(id)) => Some(ScanTarget::Container(id)),
                _ => None,
            };
            if let Some(t) = target
                && allowed.permits(t)
                && seen.insert(version.clone())
            {
                result.push(version);
            }
        }
        Ok(result)
    }

    pub async fn distinct_purls(&self) -> Result<Vec<String>, StoreError> {
        InventoryRepository::distinct_purls(&self.db).await
    }

    pub async fn distinct_purls_by_target(&self) -> Result<Vec<(Option<i64>, Option<i64>, String)>, StoreError> {
        InventoryRepository::distinct_purls_by_target(&self.db).await
    }

    pub async fn distinct_repositories_with_components(&self) -> Result<Vec<i64>, StoreError> {
        InventoryRepository::distinct_repositories_with_components(&self.db).await
    }

    pub async fn distinct_containers_with_components(&self) -> Result<Vec<i64>, StoreError> {
        InventoryRepository::distinct_containers_with_components(&self.db).await
    }
}
