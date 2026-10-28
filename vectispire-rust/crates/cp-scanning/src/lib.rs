//! The control plane's `scanning` module, `core.scanning` — Phase 2, task 2.7 of the port: the queue several instances
//! share and its claim, the dispatcher that hands a scan to a remote agent or to the built-in worker and writes what
//! comes back, the leader lease and the scheduler that queues what is due, the retention of raw payloads, the purge
//! of a deleted target's scans, the catalogue other modules read, and the three scan routes.
//!
//! The module's places, as `cp-arch-tests` reads them: the root files are its API and services ([`Scanning`] and the
//! files beside it, one per Java service); `internal` the queue, the leader lease, the maintenance tasks and the
//! `TargetScans` `targets` declares; `persistence` every statement on `t_scan`, `t_leader_lease` and `t_finding`; `web`
//! the routes. **Ingestion is task 2.8's** — `ingestion.rs`, `internal/ingestion/`, `persistence/findings.rs`, declared
//! here and empty until it lands; the dispatcher reaches it through [`ports::ScanIngestor`].
//!
//! **What it may use** is `edges.toml`'s line: `access` (visibility, the row guards), `access::security` for its routes,
//! `targets` (a scan is of a target: the dispatcher reads its row and credentials, the scheduler its schedule), and the
//! shared foundation. What it needs of the modules above is a port it declares ([`ports`]), each with a named stand-in.
//!
//! **A role marker is not authorization** (AGENTS.md): every route is `.scoped()` and hands the caller's allowance to
//! the service, which applies it in the query or refuses as the absence it must look like.

#![forbid(unsafe_code)]

pub mod catalog;
pub mod dispatcher;
pub mod error;
pub mod ingestion;
mod instants;
mod internal;
mod persistence;
pub use persistence::StoreError;
pub mod ports;
pub mod purge;
pub mod query;
pub mod retention;
pub mod scheduler;
pub mod trigger;
pub mod views;
mod web;

use std::sync::Arc;
use std::time::Duration;

use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::Db;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::{AuditSink, Clock, Targets};
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::scan_queue::Policy;

pub use catalog::ScanCatalog;
pub use dispatcher::{ClaimingAgent, ScanDispatcher};
pub use error::ScanError;
pub use internal::leader::{DEFAULT_LEASE, JOB_SCHEDULER, LeaderElection};
pub use internal::queue::{
    Abandoned, AgentClaim, ERROR_MAX_LENGTH, Exclusion, NoExclusion, PAGE, PAGES, Reclaimed, ScanQueue, truncate,
};
pub use internal::worker::{BuiltInScanRunner, ScanWorker, WorkerProperties};
pub use internal::{ScanRetentionTask, SchedulingTickTask, TargetScanFigures};
pub use views::{FindingOnScan, NewestCompletedScanRow, PackageImpact, ScanFindingView, ScanSbom, ScanView};
pub use web::routes;

/// The module's services, composed once.
pub struct Scanning {
    pub(crate) db: Db,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) settings: Settings,
    pub(crate) targets: Arc<Targets>,
    pub(crate) catalog: ScanCatalog,
    pub(crate) queue: Arc<ScanQueue>,
    pub(crate) election: LeaderElection,
    pub(crate) dispatcher: Arc<ScanDispatcher>,
}

impl std::fmt::Debug for Scanning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Scanning")
            .field("db", &self.db)
            .field("queue", &self.queue)
            .field("election", &self.election)
            .field("dispatcher", &self.dispatcher)
            .finish_non_exhaustive()
    }
}

/// What [`Scanning`] is built from.
#[allow(missing_debug_implementations)] // Ports and a pool: nothing a log line should print.
pub struct ScanningConfig {
    pub db: Db,
    pub clock: Arc<dyn Clock>,
    /// `targets`, composed first over [`target_scans`]: the dispatcher reads its rows and credentials, the scheduler
    /// its schedules and stamps.
    pub targets: Arc<Targets>,
    pub encryption: Arc<Encryption>,
    pub audit: Arc<dyn AuditSink>,
    /// `agents`' row lock, or [`ports::AgentsStandIn`] until task 2.9.
    pub claim_lock: Arc<dyn ports::AgentClaimLock>,
    /// `rules`' answer, or [`ports::BundledRules`] until Phase 3.
    pub rule_sets: Arc<dyn ports::ScanRuleSets>,
    /// `plugins`' answer, or [`ports::NoPlugins`] until Phase 4.
    pub plugins: Arc<dyn ports::ScanPlugins>,
    /// Task 2.8's ingestion, or [`ports::IngestionStandIn`] until it lands.
    pub ingestor: Arc<dyn ports::ScanIngestor>,
    /// `vectispire.scanning.*`: the lease, the attempts, the retry delays.
    pub policy: Policy,
    /// `vectispire.leader.lease`, at least a second.
    pub leader_lease: Duration,
    /// `vectispire.git.allowed-hosts`, checked again when a task is built.
    pub allowed_hosts: GitHostAllowlist,
    /// `vectispire.scanning.image-platform`.
    pub image_platform: Option<String>,
    /// The built-in worker's runner (2.10), `None` on a control plane served by remote agents alone.
    pub runner: Option<Arc<dyn ports::ScanRunner>>,
    /// `RepositoryScanned` reactions (Phase 5): none yet.
    pub scanned: Vec<Arc<dyn ports::RepositoryScanned>>,
}

impl Scanning {
    pub fn new(config: ScanningConfig) -> Scanning {
        let queue = Arc::new(ScanQueue::new(config.db.clone(), config.claim_lock, config.policy, config.clock.clone()));
        let dispatcher = Arc::new(ScanDispatcher::new(dispatcher::DispatcherConfig {
            queue: Arc::new(dispatcher::QueueOnDatabase { queue: queue.clone(), db: config.db.clone() }),
            targets: config.targets.clone(),
            encryption: config.encryption,
            sast: Arc::new(Settings::new(config.db.clone())),
            rule_sets: config.rule_sets,
            plugins: config.plugins,
            ingestor: config.ingestor,
            audit: config.audit,
            allowed_hosts: config.allowed_hosts,
            image_platform: config.image_platform,
            runner: config.runner,
            scanned: config.scanned,
        }));
        Scanning {
            settings: Settings::new(config.db.clone()),
            catalog: ScanCatalog::new(config.db.clone(), config.clock.clone()),
            election: LeaderElection::new(config.db.clone(), config.leader_lease, config.clock.clone()),
            db: config.db,
            clock: config.clock,
            targets: config.targets,
            queue,
            dispatcher,
        }
    }

    pub fn queue(&self) -> &Arc<ScanQueue> {
        &self.queue
    }

    pub fn dispatcher(&self) -> &ScanDispatcher {
        &self.dispatcher
    }

    pub fn dispatcher_arc(&self) -> Arc<ScanDispatcher> {
        self.dispatcher.clone()
    }

    pub fn election(&self) -> &LeaderElection {
        &self.election
    }

    pub fn catalog(&self) -> &ScanCatalog {
        &self.catalog
    }
}

/// `targets`' `TargetScans`, over the catalogue alone — what `TargetsConfig::scans` takes in place of
/// `ScanningStandIn`, built before [`Targets`] and therefore before [`Scanning`].
pub fn target_scans(db: Db, clock: Arc<dyn Clock>) -> Arc<dyn vectispire_cp_targets::TargetScans> {
    Arc::new(TargetScanFigures(ScanCatalog::new(db, clock)))
}

/// The maintenance tasks this module contributes: `SCHEDULING_TICK` and `SCAN_RETENTION`.
pub fn tasks(scanning: Arc<Scanning>) -> Vec<Arc<dyn vectispire_cp_maintenance::MaintenanceTask>> {
    vec![Arc::new(SchedulingTickTask(scanning.clone())), Arc::new(ScanRetentionTask(scanning))]
}
