//! Threat intelligence — Java's `core/threatintel`: the CISA KEV catalogue and FIRST's EPSS file, each read whole or
//! not at all, the backlog's exploitation re-evaluated against them, and the ranking of the open vulnerabilities.
//!
//! **The pure decisions are this crate's root files, not `vectispire-domain`'s**: the agent links that crate, and
//! nothing here is the agent's — the reader of the EPSS file links zlib besides. They are held to
//! `reference/threatintel/`, which `ThreatIntelReferenceSetTest` writes from the Java classes.

#![forbid(unsafe_code)]

pub mod end_of_life;
pub mod enrichment;
pub mod epss_feed;
pub mod epss_file;
pub mod feeds;
pub mod kev_catalog;
pub mod life_cycle;
mod persistence;
pub mod prioritization;
pub mod risk_matrix;
pub mod sources;
pub mod status;
pub mod sync;
mod tasks;
mod time_text;
mod web;

pub use tasks::{EpssScoresSyncTask, KevCatalogueSyncTask};
pub use web::{Services, routes};

use std::sync::Arc;

use epss_feed::EpssFeed;
use feeds::ThreatIntel;
use prioritization::EpssPrioritizationService;
use sources::{EpssSource, KevSource};
use sync::ThreatIntelFeedService;

/// What the module is composed over.
#[allow(missing_debug_implementations)] // pools and ports
pub struct ThreatIntelParts {
    pub db: vectispire_cp_db::Db,
    pub issues: Arc<vectispire_cp_issues::queries::IssueCatalog>,
    pub targets: Arc<vectispire_cp_targets::Targets>,
    pub clock: Arc<dyn vectispire_cp_targets::Clock>,
    /// Where `CRITICAL_KEV_DETECTED` goes: the SIEM module's events, handed in by the binary.
    pub events: Arc<dyn vectispire_cp_outbox::SecurityEvents>,
    pub audit: Arc<vectispire_cp_audit::AuditLog>,
    pub catalogue: Arc<dyn KevSource>,
    pub file: Arc<dyn EpssSource>,
}

impl Services {
    /// The module as the binary composes it: the feeds over the module's tables, the ranking over the backlog and the
    /// targets' names, the synchronisations over the two sources. Here, not in `web`: a route holds nothing of the
    /// pool.
    pub fn new(parts: ThreatIntelParts) -> Services {
        let ThreatIntelParts { db, issues, targets, clock, events, audit, catalogue, file } = parts;
        let feeds = ThreatIntel::new(db.clone(), clock.clone());
        let epss = EpssFeed::new(db.clone(), feeds.clone(), issues.clone(), file, clock.clone());
        let sync = Arc::new(ThreatIntelFeedService::new(db, events, audit, catalogue, epss, clock));
        Services { ranking: EpssPrioritizationService::new(issues, targets, feeds.clone()), feeds, sync }
    }

    /// The module's two slots in the hourly turn.
    pub fn tasks(&self) -> Vec<Arc<dyn vectispire_cp_maintenance::MaintenanceTask>> {
        vec![Arc::new(KevCatalogueSyncTask(self.sync.clone())), Arc::new(EpssScoresSyncTask(self.sync.clone()))]
    }
}
