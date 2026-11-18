//! Threat intelligence (wave 2) as the binary composes it: the KEV catalogue read through the outbound JSON door and
//! the EPSS file through the download door, both with the runtime's trust and the guard reserving the deployment's own
//! endpoints, from the addresses the deployment names (`vectispire.threat-intel.*`); `CRITICAL_KEV_DETECTED` through
//! the SIEM module's events.

use std::sync::Arc;

use vectispire_cp_db::Db;
use vectispire_cp_outbound::PinnedHttpSender;
use vectispire_cp_outbound::download::OutboundDownload;
use vectispire_cp_outbound::guard::OutboundUrlGuard;
use vectispire_cp_outbound::json::OutboundJson;
use vectispire_cp_threatintel::sources::{EpssFileSource, FeedLocations, KevCatalogSource};

/// What the module is composed over.
#[allow(missing_debug_implementations)] // services and pools
pub struct ThreatIntelSetup {
    pub db: Db,
    pub guard: OutboundUrlGuard,
    pub trust: vectispire_tls::TlsTrust,
    pub locations: FeedLocations,
    pub issues: Arc<vectispire_cp_issues::queries::IssueCatalog>,
    pub targets: Arc<vectispire_cp_targets::Targets>,
    pub clock: Arc<dyn vectispire_cp_targets::Clock>,
    pub events: Arc<dyn vectispire_cp_outbox::SecurityEvents>,
    pub audit: Arc<vectispire_cp_audit::AuditLog>,
}

/// The settings' four properties, as the module reads them.
pub fn locations(settings: &vectispire_cp_runtime::settings::ThreatIntel) -> FeedLocations {
    FeedLocations {
        kev_url: settings.kev_url.clone(),
        kev_allow_private: settings.kev_allow_private,
        epss_url: settings.epss_url.clone(),
        epss_allow_private: settings.epss_allow_private,
    }
}

/// The module, composed.
pub fn compose(setup: ThreatIntelSetup) -> Arc<vectispire_cp_threatintel::Services> {
    let ThreatIntelSetup { db, guard, trust, locations, issues, targets, clock, events, audit } = setup;
    let sender = PinnedHttpSender::new(trust);
    let catalogue = KevCatalogSource::new(OutboundJson::new(sender.clone(), guard.clone()), &locations);
    let file = EpssFileSource::new(OutboundDownload::new(sender, guard), &locations);
    Arc::new(vectispire_cp_threatintel::Services::new(vectispire_cp_threatintel::ThreatIntelParts {
        db,
        issues,
        targets,
        clock,
        events,
        audit,
        catalogue: Arc::new(catalogue),
        file: Arc::new(file),
    }))
}
