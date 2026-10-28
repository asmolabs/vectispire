//! Build SBOM inventory and scan completion service (G10, Decision 0039).

use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode, ScanTarget, Tx};
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_scanning::ingestion::ScanOrigin;

use crate::build_sbom::{AcceptedBuildSbom, BuildSbom, BuildSbomView};
use crate::component::{BuildComponent, ComponentOrigin, InventoryCompletion, ScannedComponent};
use crate::persistence::{
    ComponentRow, InventoryRepository, NewBuildSbom, NewBuildSbomComponent, NewComponent, StoreError,
};

#[derive(Debug, Clone)]
pub struct BuildSbomInventory {
    db: Db,
    scans: Arc<ScanCatalog>,
}

impl BuildSbomInventory {
    pub const HISTORY_LIMIT: i64 = 50;
    pub const PURGE_BATCH: i64 = 1_000;
    pub const PURGE_BATCHES: usize = 50;

    pub fn new(db: Db, scans: Arc<ScanCatalog>) -> Self {
        Self { db, scans }
    }

    pub async fn record(
        &self,
        tx: &mut Tx,
        accepted: AcceptedBuildSbom,
        sbom: BuildSbom,
    ) -> Result<BuildSbomView, StoreError> {
        let new_import = NewBuildSbom {
            source_id: accepted.source_id,
            source_slug: accepted.source_slug.clone(),
            repo_id: accepted.repo_id,
            spec_version: sbom.spec_version.clone(),
            tool: sbom.tool.clone(),
            components_count: i32::try_from(sbom.components.len()).unwrap_or(0),
            commit_sha: accepted.commit.clone(),
            branch_name: accepted.branch.clone(),
            document_sha256: accepted.document_sha256.clone(),
            imported_at: accepted.imported_at,
            imported_by: accepted.imported_by.clone(),
            api_key_id: accepted.api_key_id.clone(),
        };

        let import_id = InventoryRepository::insert_build_sbom(tx, &new_import).await?;

        let components: Vec<NewBuildSbomComponent> = sbom
            .components
            .iter()
            .map(|c| NewBuildSbomComponent {
                import_id,
                name: c.name.clone(),
                version: c.version.clone(),
                purl: c.purl.clone(),
                type_: c.r#type.clone(),
                license: c.license.clone(),
            })
            .collect();

        InventoryRepository::insert_build_sbom_components(tx, &components).await?;

        // Complete within the same transaction
        let completed = self.complete_newest_tx(tx, accepted.repo_id).await?;

        Ok(BuildSbomView {
            id: import_id,
            source_id: accepted.source_id,
            source_slug: accepted.source_slug,
            repo_id: accepted.repo_id,
            spec_version: sbom.spec_version,
            tool: sbom.tool,
            components_count: i32::try_from(sbom.components.len()).unwrap_or(0),
            commit: accepted.commit,
            branch: accepted.branch,
            document_sha256: accepted.document_sha256,
            imported_at: accepted.imported_at,
            imported_by: accepted.imported_by,
            completed_scan_id: completed,
        })
    }

    pub async fn complete_newest(&self, repository_id: i64) -> Result<Option<i64>, StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(StoreError::from)?;
        let result = self.complete_newest_tx(&mut tx, repository_id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(result)
    }

    pub async fn complete_newest_tx(&self, tx: &mut Tx, repository_id: i64) -> Result<Option<i64>, StoreError> {
        let target = ScanTarget::Repository(repository_id);
        let newest_map = self.scans.newest_completed(&[target]).await.map_err(|e| StoreError::Other(e.to_string()))?;
        let newest = match newest_map.get(&target) {
            Some(n) => n,
            None => return Ok(None),
        };

        let count = InventoryRepository::count_components_by_scan_ids(&self.db, &[newest.scan_id]).await?;
        if !newest.sbom_stored && count == 0 {
            return Ok(None);
        }

        let origin = ScanOrigin {
            id: newest.scan_id,
            repo_id: Some(repository_id),
            container_id: None,
            created_at: newest.created_at,
        };

        self.complete_tx(tx, origin).await?;
        Ok(Some(newest.scan_id))
    }

    pub async fn complete(&self, scan: ScanOrigin) -> Result<(), StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(StoreError::from)?;
        self.complete_tx(&mut tx, scan).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(())
    }

    pub async fn complete_tx(&self, tx: &mut Tx, scan: ScanOrigin) -> Result<(), StoreError> {
        let repo_id = match scan.repo_id {
            Some(id) => id,
            None => return Ok(()),
        };

        let labels = self.scans.labels_of(&[scan.id]).await.map_err(|e| StoreError::Other(e.to_string()))?;
        let branch = labels.get(&scan.id).map(|l| l.branch.as_str());

        let build_opt = InventoryRepository::find_newest_build_sbom_for_repo(tx, repo_id, branch).await?;

        let rows = InventoryRepository::lock_scan_components(tx, scan.id).await?;
        let from_build: Vec<&ComponentRow> =
            rows.iter().filter(|r| ComponentOrigin::of_stored(r.origin.as_deref()).from_build()).collect();

        if let Some(ref build) = build_opt
            && !from_build.is_empty()
            && from_build.iter().all(|r| r.build_sbom_id == Some(build.id))
        {
            return Ok(());
        }

        if build_opt.is_none() && from_build.is_empty() {
            return Ok(());
        }

        let mut added_ids = Vec::new();
        let mut scanner_rows = Vec::new();

        for mut row in rows {
            match ComponentOrigin::of_stored(row.origin.as_deref()) {
                ComponentOrigin::Build => {
                    added_ids.push(row.id);
                }
                ComponentOrigin::Both => {
                    row.version = row.scanned_version.clone();
                    row.purl = row.scanned_purl.clone();
                    row.origin = None;
                    row.build_sbom_id = None;
                    row.scanned_version = None;
                    row.scanned_purl = None;
                    row.declared_license = None;
                    scanner_rows.push(row);
                }
                ComponentOrigin::Scanner => {
                    scanner_rows.push(row);
                }
            }
        }

        InventoryRepository::delete_components_by_ids(tx, &added_ids).await?;

        let build = match build_opt {
            Some(b) => b,
            None => {
                InventoryRepository::update_components(tx, &scanner_rows).await?;
                return Ok(());
            }
        };

        let stated_components = InventoryRepository::find_build_sbom_components(tx, build.id).await?;
        let stated: Vec<BuildComponent> = stated_components
            .into_iter()
            .map(|r| BuildComponent {
                name: r.name,
                version: r.version,
                purl: r.purl,
                r#type: r.type_,
                license: r.license,
            })
            .collect();

        let scanned_components: Vec<ScannedComponent> = scanner_rows
            .iter()
            .map(|r| ScannedComponent {
                id: r.id,
                name: r.name.clone(),
                version: r.version.clone(),
                purl: r.purl.clone(),
            })
            .collect();

        let plan = InventoryCompletion::of(&scanned_components, &stated);

        let mut scanner_map: HashMap<i64, &mut ComponentRow> = scanner_rows.iter_mut().map(|r| (r.id, r)).collect();

        for completed in plan.completed {
            if let Some(row) = scanner_map.get_mut(&completed.id) {
                row.scanned_version = row.version.clone();
                row.scanned_purl = row.purl.clone();
                row.version = completed.version;
                row.purl = completed.purl;
                row.origin = Some(ComponentOrigin::Both.stored().unwrap_or("both").to_owned());
                row.build_sbom_id = Some(build.id);
                row.declared_license = completed.license;
            }
        }

        InventoryRepository::update_components(tx, &scanner_rows).await?;

        let new_added: Vec<NewComponent> = plan
            .added
            .into_iter()
            .map(|c| NewComponent {
                scan_id: scan.id,
                repo_id: Some(repo_id),
                container_id: None,
                scan_created_at: Some(scan.created_at),
                name: c.name,
                version: c.version,
                purl: c.purl,
                type_: c.r#type,
                is_direct: None,
                origin: Some(ComponentOrigin::Build.stored().unwrap_or("build").to_owned()),
                build_sbom_id: Some(build.id),
                scanned_version: None,
                scanned_purl: None,
                declared_license: c.license,
            })
            .collect();

        InventoryRepository::insert_components(tx, &new_added).await?;

        Ok(())
    }

    pub async fn history(&self, repository_id: i64) -> Result<Vec<BuildSbomView>, StoreError> {
        let rows = InventoryRepository::find_build_sboms_by_repo(&self.db, repository_id, Self::HISTORY_LIMIT).await?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        let completed_pairs = InventoryRepository::newest_scan_completed_by(&self.db, &ids).await?;
        let completed_map: HashMap<i64, i64> = completed_pairs.into_iter().collect();

        Ok(rows
            .into_iter()
            .map(|r| {
                let completed_scan_id = completed_map.get(&r.id).copied();
                BuildSbomView {
                    id: r.id,
                    source_id: r.source_id,
                    source_slug: r.source_slug,
                    repo_id: r.repo_id,
                    spec_version: r.spec_version,
                    tool: r.tool,
                    components_count: r.components_count,
                    commit: r.commit_sha,
                    branch: r.branch_name,
                    document_sha256: r.document_sha256,
                    imported_at: r.imported_at,
                    imported_by: r.imported_by,
                    completed_scan_id,
                }
            })
            .collect())
    }

    pub async fn purge_imported_before(&self, cutoff: OffsetDateTime) -> Result<usize, StoreError> {
        let mut purged: usize = 0;
        for _ in 0..Self::PURGE_BATCHES {
            let mut tx = self.db.begin(Mode::ReadWrite).await.map_err(StoreError::from)?;
            let ids =
                InventoryRepository::find_build_sbom_ids_imported_before(&mut tx, cutoff, Self::PURGE_BATCH).await?;
            if ids.is_empty() {
                break;
            }
            InventoryRepository::delete_build_sbom_components_by_import_ids(&mut tx, &ids).await?;
            let count = InventoryRepository::delete_build_sboms_by_ids(&mut tx, &ids).await?;
            tx.commit().await.map_err(StoreError::from)?;
            purged = purged.saturating_add(usize::try_from(count).unwrap_or(0));
        }
        Ok(purged)
    }
}
