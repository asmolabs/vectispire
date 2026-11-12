//! The scan ingestor as the control plane composes it — here rather than inline in `main`, so that
//! `tests/ingestion_composition.rs` can hold the composition itself.
//!
//! **Why that test exists.** The binary built its ingestor with no licence source, no enrichment and no end of life,
//! three `None`s nobody named: no licence finding was ever raised, and every vulnerability went to the gate as not
//! exploited. Java composes all three unconditionally (`@Service`). No test of the ingestor could see it — the
//! reference set states its sources per case — which is the `MaintenanceJobsTest` lesson of `AGENTS.md`.

use std::sync::Arc;

use vectispire_cp_scanning::ingestion::{
    Backlog, EndOfLifeStandIn, EnrichmentStandIn, InventorySink, LicenseService, ScanIngestor,
};
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::Clock;

/// Java's `ScanIngestor` bean: the licences read from the settings at each scan, and the two `threatintel` sources as
/// named stand-ins until Phase 4 task 4.4 ports them.
pub fn ingestor(
    backlog: Arc<dyn Backlog>,
    inventory: Arc<dyn InventorySink>,
    settings: Settings,
    clock: Arc<dyn Clock>,
) -> ScanIngestor {
    ScanIngestor::new(
        backlog,
        inventory,
        Some(Arc::new(EnrichmentStandIn)),
        Some(Arc::new(EndOfLifeStandIn)),
        Some(Arc::new(LicenseService::from_settings(settings))),
        clock,
    )
}
