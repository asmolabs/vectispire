//! The scan ingestor as the control plane composes it — here rather than inline in `main`, so that
//! `tests/ingestion_composition.rs` can hold the composition itself.
//!
//! **Why that test exists.** The binary built its ingestor with no licence source, no enrichment and no end of life,
//! three `None`s nobody named: no licence finding was ever raised, and every vulnerability went to the gate as not
//! exploited. Java composes all three unconditionally (`@Service`). No test of the ingestor could see it — the
//! reference set states its sources per case — which is the `MaintenanceJobsTest` lesson of `AGENTS.md`.

use std::sync::Arc;

use vectispire_cp_db::Db;
use vectispire_cp_outbound::guard::OutboundUrlGuard;
use vectispire_cp_outbound::json::OutboundJson;
use vectispire_cp_scanning::ingestion::{Backlog, InventorySink, LicenseService, ScanIngestor};
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::Clock;
use vectispire_cp_threatintel::end_of_life::EndOfLifeService;
use vectispire_cp_threatintel::enrichment::EnrichmentService;
use vectispire_cp_threatintel::feeds::ThreatIntel;

/// What the ingestor reads besides the backlog and the inventory.
#[allow(missing_debug_implementations)] // pools
pub struct IngestionSources {
    pub db: Db,
    pub settings: Settings,
    pub clock: Arc<dyn Clock>,
    /// The end-of-life catalog's door: endoflife.date, public only, with the runtime's trust.
    pub guard: OutboundUrlGuard,
    pub trust: vectispire_tls::TlsTrust,
}

/// Java's `ScanIngestor` bean: the licences read from the settings at each scan, the enrichment from the stored
/// threat feeds, and end of life from endoflife.date.
pub fn ingestor(
    backlog: Arc<dyn Backlog>,
    inventory: Arc<dyn InventorySink>,
    sources: IngestionSources,
) -> ScanIngestor {
    let IngestionSources { db, settings, clock, guard, trust } = sources;
    let enrichment = EnrichmentService::new(db.clone(), settings.clone(), ThreatIntel::new(db, clock.clone()));
    let catalog = OutboundJson::new(vectispire_cp_outbound::PinnedHttpSender::new(trust), guard);
    let end_of_life = EndOfLifeService::new(settings.clone(), Arc::new(catalog), clock.clone());
    ScanIngestor::new(
        backlog,
        inventory,
        Some(Arc::new(enrichment)),
        Some(Arc::new(end_of_life)),
        Some(Arc::new(LicenseService::from_settings(settings))),
        clock,
    )
}
