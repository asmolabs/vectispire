//! Threat intelligence — Java's `core/threatintel`: the CISA KEV catalogue and FIRST's EPSS file, each read whole or
//! not at all, the backlog's exploitation re-evaluated against them, and the ranking of the open vulnerabilities.
//!
//! **The pure decisions are this crate's root files, not `vectispire-domain`'s**: the agent links that crate, and
//! nothing here is the agent's — the reader of the EPSS file links zlib besides. They are held to
//! `reference/threatintel/`, which `ThreatIntelReferenceSetTest` writes from the Java classes.

#![forbid(unsafe_code)]

pub mod epss_file;
pub mod feeds;
pub mod kev_catalog;
mod persistence;
pub mod prioritization;
pub mod risk_matrix;
pub mod status;
mod web;

pub use web::{Services, routes};

use std::sync::Arc;

use feeds::ThreatIntel;
use prioritization::EpssPrioritizationService;

impl Services {
    /// The read side as the binary composes it: the feeds over the module's tables, the ranking over the backlog and
    /// the targets' names. Here, not in `web`: a route holds nothing of the pool.
    pub fn new(
        db: vectispire_cp_db::Db,
        issues: Arc<vectispire_cp_issues::queries::IssueCatalog>,
        targets: Arc<vectispire_cp_targets::Targets>,
        clock: Arc<dyn vectispire_cp_targets::Clock>,
    ) -> Services {
        let feeds = ThreatIntel::new(db, clock);
        Services { ranking: EpssPrioritizationService::new(issues, targets, feeds.clone()), feeds }
    }
}
