//! Inventory backfill: indexes components of scans that ran before the inventory existed.
//!
//! Because the answer was already stored, and unreachable. Every scan keeps its SBOM whole, so the component list
//! of every past scan is on disk; only the index was missing. Without this, "which of our releases shipped log4j 2.14.1"
//! would answer "no data" for the entire history.
//!
//! It takes scans that have an SBOM and no components, a batch at a time, so a large installation converges over
//! several ticks instead of holding a transaction open across ten thousand scans.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::Value;
use vectispire_cp_db::Db;
use vectispire_cp_scanning::catalog::ScanCatalog;
use vectispire_cp_scanning::ingestion::ScanOrigin;
use vectispire_domain::dependency_graph::DependencyGraph;

use crate::component_inventory::ComponentInventory;
use crate::error::InventoryError;
use crate::persistence::repository::InventoryRepository;

/// Up to fifty scans per turn, bounded so one tick is never a long transaction.
pub const BATCH: usize = 50;

/// Identifiers per page: an in-list every engine takes, far below any bind limit.
pub const PAGE: i64 = 500;

/// Backfills the component inventory from past scans holding an SBOM.
#[derive(Clone, Debug)]
pub struct InventoryBackfill {
    scans: ScanCatalog,
    inventory: Arc<ComponentInventory>,
    db: Db,
    page: i64,
}

impl InventoryBackfill {
    pub fn new(scans: ScanCatalog, inventory: Arc<ComponentInventory>, db: Db) -> Self {
        Self::with_page(scans, inventory, db, PAGE)
    }

    pub fn with_page(scans: ScanCatalog, inventory: Arc<ComponentInventory>, db: Db, page: i64) -> Self {
        Self { scans, inventory, db, page }
    }

    /// Indexes unindexed scans holding an SBOM, up to one batch.
    pub async fn run_once(&self) -> Result<usize, InventoryError> {
        let pending = self.unindexed().await?;
        if pending.is_empty() {
            return Ok(0);
        }

        let mut indexed: usize = 0;
        for scan_id in pending {
            let scan = match self.scans.scan(scan_id).await {
                Ok(Some(s)) => s,
                Ok(None) => continue,
                Err(err) => {
                    tracing::warn!("Inventory backfill: could not read scan {scan_id}: {err}");
                    continue;
                }
            };

            let raw_sbom = match self.scans.sbom(scan_id).await {
                Ok(Some(raw)) => raw,
                Ok(None) => continue,
                Err(err) => {
                    tracing::warn!("Inventory backfill: could not read SBOM for scan {scan_id}: {err}");
                    continue;
                }
            };

            match serde_json::from_str::<Value>(&raw_sbom) {
                Ok(sbom) => {
                    let graph = DependencyGraph::new(Some(&sbom));
                    let origin = ScanOrigin::of(&scan);
                    if let Err(err) = self.inventory.record(None, origin, &sbom, &graph).await {
                        tracing::warn!("Inventory backfill: recording scan {scan_id} components failed: {err}");
                    } else {
                        indexed = indexed.saturating_add(1);
                    }
                }
                Err(unreadable) => {
                    // Stored payload could not be parsed: retry next pass, and log so it is visible
                    // rather than silently absent from every search.
                    tracing::warn!("Inventory backfill: the SBOM of scan {scan_id} could not be read: {unreadable}");
                }
            }
        }

        if indexed > 0 {
            tracing::info!("Inventory backfill: {indexed} scan(s) indexed.");
        }
        Ok(indexed)
    }

    /// Up to a batch of the newest scans holding an SBOM that have no component row.
    async fn unindexed(&self) -> Result<Vec<i64>, InventoryError> {
        let mut pending = Vec::new();
        let mut before = i64::MAX;

        while pending.len() < BATCH {
            let ids = self.scans.ids_with_sbom_before(before, self.page).await?;
            if ids.is_empty() {
                break;
            }

            let indexed_vec = InventoryRepository::indexed_among(&self.db, &ids).await?;
            let indexed: HashSet<i64> = indexed_vec.into_iter().collect();

            for id in &ids {
                if !indexed.contains(id) {
                    pending.push(*id);
                    if pending.len() >= BATCH {
                        break;
                    }
                }
            }

            if let Some(last) = ids.last() {
                before = *last;
            } else {
                break;
            }
        }

        Ok(pending)
    }
}
