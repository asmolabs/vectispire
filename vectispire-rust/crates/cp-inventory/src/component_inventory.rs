//! Storing SBOM components into `t_component`.

use serde_json::Value;
use vectispire_cp_db::{Db, Mode, Tx};
use vectispire_cp_scanning::ingestion::ScanOrigin;
use vectispire_domain::dependency_graph::{DependencyGraph, Directness};

use crate::component::ComponentOrigin;
use crate::persistence::{InventoryRepository, NewComponent, StoreError};

#[derive(Debug, Clone)]
pub struct ComponentInventory {
    db: Db,
}

impl ComponentInventory {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn record(
        &self,
        tx: Option<&mut Tx>,
        scan: ScanOrigin,
        sbom: &Value,
        graph: &DependencyGraph,
    ) -> Result<usize, StoreError> {
        let artifacts = match sbom.get("artifacts").and_then(|a| a.as_array()) {
            Some(arr) => arr,
            None => return Ok(0),
        };

        if let Some(tx) = tx {
            Self::record_tx(tx, scan, artifacts, graph).await
        } else {
            let mut new_tx = self.db.begin(Mode::ReadWrite).await.map_err(StoreError::from)?;
            let count = Self::record_tx(&mut new_tx, scan, artifacts, graph).await?;
            new_tx.commit().await.map_err(StoreError::from)?;
            Ok(count)
        }
    }

    pub async fn record_tx(
        tx: &mut Tx,
        scan: ScanOrigin,
        artifacts: &[Value],
        graph: &DependencyGraph,
    ) -> Result<usize, StoreError> {
        InventoryRepository::delete_components_by_scan_id(tx, scan.id).await?;

        let mut rows = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            let name = match artifact.get("name").and_then(|v| v.as_str()) {
                Some(n) if !n.trim().is_empty() => n.trim(),
                _ => continue,
            };
            let version = artifact.get("version").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty());
            let purl = artifact.get("purl").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty());
            let type_ = artifact.get("type").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty());

            let is_direct = match graph.of(purl, Some(name), version) {
                Directness::Direct => Some(true),
                Directness::Transitive => Some(false),
                Directness::Unknown => None,
            };

            rows.push(NewComponent {
                scan_id: scan.id,
                repo_id: scan.repo_id,
                container_id: scan.container_id,
                scan_created_at: Some(scan.created_at),
                name: trim(name, 255),
                version: version.map(|v| trim(v, 255)),
                purl: purl.map(|p| trim(p, 500)),
                type_: type_.map(|t| trim(t, 50)),
                is_direct,
                origin: ComponentOrigin::Scanner.stored().map(|s| s.to_owned()),
                build_sbom_id: None,
                scanned_version: None,
                scanned_purl: None,
                declared_license: None,
            });
        }

        let count = rows.len();
        InventoryRepository::insert_components(tx, &rows).await?;
        Ok(count)
    }
}

fn trim(value: &str, max: usize) -> String {
    if value.chars().count() <= max { value.to_owned() } else { value.chars().take(max).collect() }
}
