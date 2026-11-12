//! Target purge listeners for the inventory module:
//! - `BuildSbomPurge` (Phase::References, repository build SBOMs and components)
//! - `ComponentPurge` (Phase::ScanChildren, scan components)

use std::sync::Arc;

use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::{ListenerName, Phase, PurgeListener, TargetPurge};

use crate::persistence::InventoryRepository;

pub const BATCH: usize = 1_000;

/// `BuildSbomPurge.purge`, in the references phase (does not hear orphan sweep).
#[derive(Debug, Clone, Copy, Default)]
pub struct BuildSbomPurge;

impl PurgeListener for BuildSbomPurge {
    fn name(&self) -> ListenerName {
        ListenerName { module: "inventory", listener: "BuildSbomPurge.purge" }
    }

    fn phase(&self) -> Phase {
        Phase::References
    }

    fn purge<'a>(
        &'a self,
        tx: &'a mut Tx,
        purge: &'a TargetPurge,
    ) -> BoxFuture<'a, Result<(), vectispire_cp_targets::deletion::PurgeError>> {
        Box::pin(async move {
            if let TargetPurge::Deleted(ScanTarget::Repository(id)) = purge {
                let ids = InventoryRepository::find_build_sbom_ids_by_repo(tx, *id).await?;

                for batch in ids.chunks(BATCH) {
                    InventoryRepository::delete_build_sbom_components_by_import_ids(tx, batch).await?;
                    InventoryRepository::delete_build_sboms_by_ids(tx, batch).await?;
                }
            }
            Ok(())
        })
    }
}

/// `ComponentPurge.purge`, in the scan children phase (hears orphan sweep).
#[derive(Debug, Clone, Copy, Default)]
pub struct ComponentPurge;

impl PurgeListener for ComponentPurge {
    fn name(&self) -> ListenerName {
        ListenerName { module: "inventory", listener: "ComponentPurge.purge" }
    }

    fn phase(&self) -> Phase {
        Phase::ScanChildren
    }

    fn purge<'a>(
        &'a self,
        tx: &'a mut Tx,
        purge: &'a TargetPurge,
    ) -> BoxFuture<'a, Result<(), vectispire_cp_targets::deletion::PurgeError>> {
        Box::pin(async move {
            let scans = vectispire_cp_scanning::purge::scans_of(tx, purge).await?;

            for batch in scans.chunks(BATCH) {
                InventoryRepository::delete_components_by_scan_ids(tx, batch).await?;
            }

            Ok(())
        })
    }
}

/// Returns the inventory module's purge listeners.
pub fn listeners() -> Vec<Arc<dyn PurgeListener>> {
    vec![Arc::new(BuildSbomPurge), Arc::new(ComponentPurge)]
}
