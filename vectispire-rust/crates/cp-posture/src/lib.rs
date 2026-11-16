//! `vectispire-cp-posture`
//! Figures of risk: the dashboard, scorecards and badges, security debt, quality, remediation, attack paths and the
//! weekly digest — `core.posture`, and the parts of `common.domain` it alone or first reads (scorecards, trends,
//! remediation, attack paths, the digest's content).
//!
//! **It owns no table.** Every figure is read through the module that holds the rows — the gate's overview, the
//! issues' aggregates (`issues::queries`), the scans', the targets' names and badge tokens, the inventory's licences
//! and endpoints — and narrowed to what the caller may see, so a figure here and the screen it links to cannot
//! disagree. Hence no `persistence` layer and no `.sqlx/` cache: the statements live, checked, with their tables.

#![forbid(unsafe_code)]

macro_rules! opaque_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    )+};
}

pub mod arithmetic;
pub mod attack_path;
pub mod attack_paths;
pub mod badges;
pub mod coverage;
pub mod dashboard;
pub mod debt;
pub mod digest;
pub mod distribution;
pub mod error;
mod internal;
pub mod ports;
pub mod quality;
pub mod remediation;
pub mod scorecard;
pub mod scorecards;
pub mod simulation;
pub mod trends;
pub mod versions;
mod web;
pub mod weekly;

use std::sync::Arc;

use vectispire_cp_audit::{AuditLog, AuditLogQuery};
use vectispire_cp_db::Db;
use vectispire_cp_gate::GateService;
use vectispire_cp_http::routes::RouteEntry;
use vectispire_cp_inventory::{ApiInventoryService, LicenseGovernanceService};
use vectispire_cp_issues::{IssueCatalog, SlaService};
use vectispire_cp_maintenance::MaintenanceTask;
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::{Clock, Targets};

pub use error::PostureError;
pub use internal::WeeklyDigestTask;
pub use ports::{Destinations, DigestChannels, NotificationsStandIn};

/// What the module reads, each through the module that owns it.
pub struct PostureConfig {
    pub db: Db,
    pub gate: Arc<GateService>,
    pub issues: Arc<IssueCatalog>,
    pub sla: Arc<SlaService>,
    pub scans: Arc<ScanCatalog>,
    pub targets: Arc<Targets>,
    pub licences: Arc<LicenseGovernanceService>,
    pub apis: Arc<ApiInventoryService>,
    pub settings: Arc<Settings>,
    pub audit: Arc<AuditLog>,
    pub audit_log: Arc<AuditLogQuery>,
    /// The notifications module's channels — [`NotificationsStandIn`] until it is ported.
    pub channels: Arc<dyn DigestChannels>,
    pub clock: Arc<dyn Clock>,
}

/// The composed posture module.
pub struct PostureModule {
    pub scorecards: Arc<scorecards::SecurityScorecards>,
    pub badges: Arc<badges::ScorecardBadges>,
    pub simulations: Arc<simulation::ScoreSimulations>,
    pub dashboard: Arc<dashboard::Dashboard>,
    pub quality: Arc<quality::Quality>,
    pub debt: Arc<debt::SecurityDebt>,
    pub distributions: Arc<distribution::RemediationDistributions>,
    pub attack_paths: Arc<attack_paths::AttackPaths>,
    pub digests: Arc<weekly::PostureDigests>,
}

opaque_debug!(PostureConfig, PostureModule);

impl PostureModule {
    pub fn new(config: PostureConfig) -> PostureModule {
        let scorecards = Arc::new(scorecards::SecurityScorecards::new(
            config.db.clone(),
            config.issues.clone(),
            config.sla.clone(),
            config.scans.clone(),
            config.targets.clone(),
            config.licences.clone(),
        ));
        PostureModule {
            badges: Arc::new(badges::ScorecardBadges::new(
                config.targets.clone(),
                scorecards.clone(),
                config.audit.clone(),
            )),
            simulations: Arc::new(simulation::ScoreSimulations::new(
                scorecards.clone(),
                config.targets.clone(),
                config.db.clone(),
            )),
            dashboard: Arc::new(dashboard::Dashboard::new(
                config.db.clone(),
                config.gate.clone(),
                config.issues.clone(),
                config.sla.clone(),
                config.scans.clone(),
                scorecards.clone(),
                config.settings.clone(),
                config.clock.clone(),
            )),
            quality: Arc::new(quality::Quality::new(config.db.clone(), config.issues.clone())),
            debt: Arc::new(debt::SecurityDebt::new(config.issues.clone(), config.targets.clone())),
            distributions: Arc::new(distribution::RemediationDistributions::new(
                config.issues.clone(),
                config.sla.clone(),
                config.clock.clone(),
            )),
            attack_paths: Arc::new(attack_paths::AttackPaths::new(
                config.targets.clone(),
                config.apis.clone(),
                config.issues.clone(),
            )),
            digests: Arc::new(weekly::PostureDigests::new(
                config.settings,
                config.gate,
                config.sla,
                config.issues,
                config.audit_log,
                config.audit,
                config.channels,
                config.clock,
            )),
            scorecards,
        }
    }

    /// The eighteen routes.
    pub fn routes(&self) -> Vec<RouteEntry> {
        web::routes(self)
    }

    /// The weekly report's turn (maintenance slot `WEEKLY_DIGEST`).
    pub fn tasks(&self) -> Vec<Arc<dyn MaintenanceTask>> {
        vec![Arc::new(WeeklyDigestTask::new(self.digests.clone()))]
    }
}
