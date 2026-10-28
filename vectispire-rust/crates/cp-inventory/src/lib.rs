//! The control plane's inventory module: components, build SBOM imports,
//! API attack surface discovery, license governance, blast radius and SBOM diff.

#![forbid(unsafe_code)]

pub mod api_inventory;
pub mod api_surface;
pub mod backfill;
pub mod blast_radius;
pub mod blast_radius_graph;
pub mod build_sbom;
pub mod build_sbom_inventory;
pub mod component;
pub mod component_catalog;
pub mod component_inventory;
pub mod consolidated;
pub mod diff;
pub mod error;
pub mod inventory_query;
pub mod license;
pub mod license_governance;
pub mod purge;
pub mod sbom_diff;

mod internal;
mod persistence;
pub use persistence::StoreError;
mod web;
pub use web::routes;

use std::sync::Arc;

use vectispire_cp_audit::AuditLog;
use vectispire_cp_db::Db;
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_scanning::ingestion::InventorySink;
use vectispire_cp_targets::Targets;

pub use api_inventory::ApiInventoryService;
pub use api_surface::*;
pub use backfill::InventoryBackfill;
pub use blast_radius::BlastRadiusService;
pub use blast_radius_graph::*;
pub use build_sbom::*;
pub use build_sbom_inventory::BuildSbomInventory;
pub use component::*;
pub use component_catalog::ComponentCatalog;
pub use component_inventory::ComponentInventory;
pub use consolidated::ConsolidatedInventoryService;
pub use diff::*;
pub use error::InventoryError;
pub use internal::ScanInventory;
pub use inventory_query::InventoryQueryService;
pub use license::*;
pub use license_governance::LicenseGovernanceService;
pub use purge::listeners;
pub use sbom_diff::SbomDiffService;

/// Configuration for creating the [`Inventory`] module.
#[derive(Clone, Debug)]
pub struct InventoryConfig {
    pub db: Db,
    pub scans: Arc<ScanCatalog>,
    pub targets: Arc<Targets>,
    pub audit: Arc<AuditLog>,
}

/// The inventory module facade bundling all sub-services and adapters.
#[derive(Clone, Debug)]
pub struct Inventory {
    db: Db,
    component_inventory: Arc<ComponentInventory>,
    build_sbom_inventory: Arc<BuildSbomInventory>,
    component_catalog: Arc<ComponentCatalog>,
    inventory_query: Arc<InventoryQueryService>,
    consolidated: Arc<ConsolidatedInventoryService>,
    license_governance: Arc<LicenseGovernanceService>,
    blast_radius: Arc<BlastRadiusService>,
    api_inventory: Arc<ApiInventoryService>,
    sbom_diff: Arc<SbomDiffService>,
    sink: Arc<ScanInventory>,
}

impl Inventory {
    pub fn new(config: InventoryConfig) -> Self {
        let component_inventory = Arc::new(ComponentInventory::new(config.db.clone()));
        let build_sbom_inventory = Arc::new(BuildSbomInventory::new(config.db.clone(), config.scans.clone()));
        let component_catalog = Arc::new(ComponentCatalog::new(config.db.clone()));
        let inventory_query = Arc::new(InventoryQueryService::new(config.db.clone(), config.scans.clone()));
        let consolidated = Arc::new(ConsolidatedInventoryService::new(
            config.db.clone(),
            config.scans.clone(),
            component_catalog.clone(),
        ));
        let license_governance = Arc::new(LicenseGovernanceService::new(
            config.db.clone(),
            config.scans.clone(),
            config.targets.clone(),
            config.audit.clone(),
        ));
        let blast_radius = Arc::new(BlastRadiusService::new(config.targets.clone(), config.scans.clone()));
        let api_inventory = Arc::new(ApiInventoryService::new(config.db.clone()));
        let sbom_diff = Arc::new(SbomDiffService::new(config.db.clone(), config.scans.clone()));
        let sink = Arc::new(ScanInventory::new(component_inventory.clone(), api_inventory.clone()));

        Self {
            db: config.db,
            component_inventory,
            build_sbom_inventory,
            component_catalog,
            inventory_query,
            consolidated,
            license_governance,
            blast_radius,
            api_inventory,
            sbom_diff,
            sink,
        }
    }

    pub fn sink(&self) -> Arc<dyn InventorySink> {
        self.sink.clone()
    }

    pub fn components(&self) -> &Arc<ComponentInventory> {
        &self.component_inventory
    }

    pub fn build_sboms(&self) -> &Arc<BuildSbomInventory> {
        &self.build_sbom_inventory
    }

    pub fn catalog(&self) -> &Arc<ComponentCatalog> {
        &self.component_catalog
    }

    pub fn query(&self) -> &Arc<InventoryQueryService> {
        &self.inventory_query
    }

    pub fn consolidated(&self) -> &Arc<ConsolidatedInventoryService> {
        &self.consolidated
    }

    pub fn licenses(&self) -> &Arc<LicenseGovernanceService> {
        &self.license_governance
    }

    pub fn blast_radius(&self) -> &Arc<BlastRadiusService> {
        &self.blast_radius
    }

    pub fn apis(&self) -> &Arc<ApiInventoryService> {
        &self.api_inventory
    }

    pub fn diff(&self) -> &Arc<SbomDiffService> {
        &self.sbom_diff
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub async fn distinct_purls(&self) -> Result<Vec<String>, StoreError> {
        self.inventory_query.distinct_purls().await
    }

    pub async fn distinct_purls_by_target(&self) -> Result<Vec<(Option<i64>, Option<i64>, String)>, StoreError> {
        self.inventory_query.distinct_purls_by_target().await
    }
}

/// The maintenance tasks this module contributes: [`InventoryBackfillTask`] and [`BuildSbomRetentionTask`].
pub fn tasks(
    inventory: Arc<Inventory>,
    scans: ScanCatalog,
    settings: vectispire_cp_settings::Settings,
    clock: Arc<dyn vectispire_cp_targets::Clock>,
) -> Vec<Arc<dyn vectispire_cp_maintenance::MaintenanceTask>> {
    let backfill = Arc::new(InventoryBackfill::new(scans, inventory.components().clone(), inventory.db().clone()));
    vec![
        Arc::new(internal::InventoryBackfillTask::new(backfill)),
        Arc::new(internal::BuildSbomRetentionTask::new(inventory.build_sboms().clone(), settings, clock)),
    ]
}
