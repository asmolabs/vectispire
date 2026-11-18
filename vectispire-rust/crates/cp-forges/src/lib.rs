//! Forges (decision 0037) — `core.forges`: read-only connections to GitHub and GitLab from which repositories are
//! discovered and imported as ordinary targets, and the change-review readings the checklists judge.
//!
//! **What it may use** (`cp-arch-tests/data/edges/forges.toml`, Java's `allowedDependencies`): `targets` for the
//! import, `checklists` for the change-review port this module implements, `access::security` for its routes. The
//! outbound door, the encryption and the audit log are the foundation's.

#![forbid(unsafe_code)]

pub mod change_reviews;
pub mod connections;
pub mod discoveries;
pub mod error;
pub mod imports;
mod internal;
mod persistence;
pub mod purge;
pub mod reviews;
pub mod tasks;
pub mod token_watch;
pub mod views;
mod web;

use std::sync::Arc;

use vectispire_cp_audit::AuditLog;
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::Db;
use vectispire_cp_http::routes::RouteEntry;
use vectispire_cp_outbound::json::OutboundJson;
use vectispire_cp_settings::{Integrations, Settings};
use vectispire_cp_targets::Clock;

pub use connections::ForgeConnectionService;
pub use discoveries::ForgeDiscoveryService;
pub use error::ForgeError;
pub use imports::ForgeImports;
pub use internal::discovery::{DiscoveryBounds, DiscoveryWorker};
pub use token_watch::{ForgeTokenWatch, TokenAlerts};

/// What the module is composed over.
#[allow(missing_debug_implementations)] // services and pools
pub struct ForgeParts {
    pub db: Db,
    pub outbound: OutboundJson,
    pub integrations: Arc<Integrations>,
    pub encryption: Arc<Encryption>,
    pub settings: Settings,
    pub audit: Arc<AuditLog>,
    pub clock: Arc<dyn Clock>,
    /// The import's creations go through the targets' own gestures.
    pub targets: Arc<vectispire_cp_targets::Targets>,
    pub bounds: DiscoveryBounds,
    /// `vectispire.forges.discovery.concurrency`: two by default.
    pub concurrency: usize,
    /// The host name a discovery's claim is written under.
    pub host: String,
    /// Where a token's change of state is told: `notifications`' listener, a stand-in until it is ported.
    pub alerts: Arc<dyn TokenAlerts>,
    pub review_bounds: reviews::ReviewBounds,
}

/// The services a route reaches, shared.
#[derive(Debug)]
pub struct Services {
    pub connections: Arc<ForgeConnectionService>,
    pub discoveries: Arc<ForgeDiscoveryService>,
    pub imports: Arc<ForgeImports>,
    pub worker: DiscoveryWorker,
    pub reviews: Arc<reviews::ForgeReviewService>,
    pub token_watch: Arc<ForgeTokenWatch>,
}

impl Services {
    /// The module's maintenance tasks: `FORGE_TOKEN_WATCH` and `CHANGE_REVIEWS`.
    pub fn tasks(&self) -> Vec<Arc<dyn vectispire_cp_maintenance::MaintenanceTask>> {
        vec![
            Arc::new(tasks::TokenWatchTask(self.token_watch.clone())),
            Arc::new(tasks::ChangeReviewTask(self.reviews.clone())),
        ]
    }
}

impl Services {
    pub fn new(parts: ForgeParts) -> Services {
        let ForgeParts {
            db,
            outbound,
            integrations,
            encryption,
            settings,
            audit,
            clock,
            targets,
            bounds,
            concurrency,
            host,
            alerts,
            review_bounds,
        } = parts;
        let integrations = internal::integrations::ForgeIntegrations::new(integrations);
        let probes = internal::probes::ForgeProbes::new(outbound.clone(), integrations.clone());
        let execution = internal::discovery::DiscoveryExecution {
            db: db.clone(),
            encryption: encryption.clone(),
            outbound,
            bounds,
            integrations: integrations.clone(),
            audit: audit.clone(),
            clock: clock.clone(),
            pager_clock: Arc::new(internal::discovery::ClockForPager(clock.clone())),
        };
        let queue = internal::discovery::DiscoveryQueue::new(db.clone(), integrations.clone(), clock.clone());
        let planner = internal::planner::ImportPlanner {
            db: db.clone(),
            targets: targets.clone(),
            settings: settings.clone(),
            integrations: integrations.clone(),
            clock: clock.clone(),
        };
        let pager_clock: Arc<dyn vectispire_cp_outbound::pager::PagerClock> =
            Arc::new(internal::discovery::ClockForPager(clock.clone()));
        let reviews = Arc::new(reviews::ForgeReviewService {
            db: db.clone(),
            demand: vectispire_cp_checklists::demand::ChangeReviewDemand::new(
                db.clone(),
                Arc::new(vectispire_cp_checklists::TargetProjects(targets.clone())),
            ),
            targets: targets.clone(),
            encryption: encryption.clone(),
            outbound: execution.outbound.clone(),
            integrations: integrations.clone(),
            bounds: review_bounds,
            clock: clock.clone(),
            pager_clock,
        });
        let token_watch = Arc::new(ForgeTokenWatch::new(db.clone(), settings.clone(), alerts, clock.clone()));
        Services {
            reviews,
            token_watch,
            connections: Arc::new(ForgeConnectionService::new(
                db.clone(),
                probes,
                integrations.clone(),
                encryption,
                settings,
                audit.clone(),
                clock.clone(),
            )),
            discoveries: Arc::new(ForgeDiscoveryService::new(db, integrations.clone(), audit.clone(), clock)),
            imports: Arc::new(ForgeImports::new(planner, targets, audit)),
            worker: DiscoveryWorker::new(queue, execution, integrations, concurrency, &host),
        }
    }
}

/// The checklists' `ChangeReviews` port over the stored readings, composed apart from the services: the checklists'
/// measurer is built before the forges' routes, and needs nothing of them but the table and the registry.
pub fn change_reviews(db: Db, integrations: Arc<Integrations>) -> change_reviews::ForgeChangeReviews {
    change_reviews::ForgeChangeReviews {
        db,
        integrations: internal::integrations::ForgeIntegrations::new(integrations),
    }
}

/// The module's routes.
pub fn routes(services: Arc<Services>) -> Vec<RouteEntry> {
    web::routes(services)
}
