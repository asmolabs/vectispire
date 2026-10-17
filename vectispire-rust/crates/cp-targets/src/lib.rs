//! The control plane's `targets` module, `core.targets` — Phase 2, task 2.6 of the port: the estate an account
//! declares. Solutions and their projects; the repositories and container images filed in them; the clone
//! credentials (HTTPS tokens, SSH keys) encrypted under Java's contexts; schedules; a repository's identity, its
//! duplicates and their keying; imports; and a target's deletion, atomic with every row that names it, through the
//! purge each owner runs.
//!
//! The module's places, as `cp-arch-tests` reads them: the root files are its API and services ([`Targets`] and the
//! files beside it, one per Java service); `internal` the maintenance tasks and the ports `access` declares that
//! this module answers; `persistence` every statement on its six tables; `web` the twenty-nine routes.
//!
//! **What it may use** is `edges.toml`'s line: `access` (the visibility, the row guards, the grants a deletion
//! revokes), `access::security` for its routes, and the shared foundation (`audit`, `crypto`, `settings`,
//! `maintenance`). What it needs of the modules above — the scan queue and the backlog's figures — are ports it
//! declares ([`TargetScans`], [`TargetBacklog`]), so every module that names a target can depend on it.
//!
//! **A role marker is not authorization** (AGENTS.md, the first trap): every route naming a target is `.scoped()`,
//! hands the caller's allowance to the service, and refuses through `cp-access`'s row guards — a 404 that reads
//! exactly like an absence. `tests/authorization_coverage.rs` walks the router to prove it for each route.

#![forbid(unsafe_code)]

pub mod audit;
pub mod catalog;
pub mod clock;
pub mod containers;
pub mod credentials;
pub mod deletion;
pub mod error;
pub mod identity;
pub mod imports;
mod internal;
pub mod naming;
mod persistence;
pub mod ports;
pub mod repositories;
pub mod schedule;
pub mod solutions;
pub mod tree;
pub mod views;
mod web;

use std::sync::Arc;

use vectispire_cp_access::VisibilityService;
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::Db;
use vectispire_cp_settings::Settings;
use vectispire_domain::cron::crontab;
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::schedules::{self, InForce};

pub use audit::AuditSink;
pub use clock::{Clock, SystemClock};
pub use deletion::{ListenerName, Phase, PurgeListener, PurgeRegistry, TargetPurge};
pub use error::TargetError;
pub use internal::{IssuerSeesTargets, OrphanedTargetRowsTask, RepositoryIdentityTask, TargetsForAccess};
pub use ports::{IssuesStandIn, ScanningStandIn, TargetBacklog, TargetScans};
pub use web::routes;

/// The module's services, composed once: what Java's ten `@Service` classes of `core.targets` shared.
pub struct Targets {
    pub(crate) db: Db,
    pub(crate) audit: Arc<dyn AuditSink>,
    pub(crate) scans: Arc<dyn TargetScans>,
    pub(crate) backlog: Arc<dyn TargetBacklog>,
    pub(crate) purge: PurgeRegistry,
    pub(crate) encryption: Arc<Encryption>,
    pub(crate) settings: Settings,
    pub(crate) allowed_hosts: GitHostAllowlist,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) visibility: Option<VisibilityService>,
}

impl std::fmt::Debug for Targets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Targets")
            .field("db", &self.db)
            .field("purge", &self.purge)
            .field("allowed_hosts", &self.allowed_hosts)
            .finish_non_exhaustive()
    }
}

/// What [`Targets`] is built from.
#[allow(missing_debug_implementations)] // Ports and a pool: nothing a log line should print.
pub struct TargetsConfig {
    pub db: Db,
    pub audit: Arc<dyn AuditSink>,
    /// `scanning`'s answer, or [`ScanningStandIn`] until task 2.7.
    pub scans: Arc<dyn TargetScans>,
    /// `issues`' answer, or [`IssuesStandIn`] until Phase 3.
    pub backlog: Arc<dyn TargetBacklog>,
    /// Every owner's purge; [`PurgeRegistry::stand_ins`] names Java's listeners until they are ported.
    pub purge: PurgeRegistry,
    pub encryption: Arc<Encryption>,
    /// `vectispire.git.allowed-hosts`, parsed at start: an entry that is not a host refuses the start.
    pub allowed_hosts: GitHostAllowlist,
    pub clock: Arc<dyn Clock>,
    /// For the import's preview of who sees what; the routes resolve their caller's through the chain.
    pub visibility: Option<VisibilityService>,
}

impl Targets {
    pub fn new(config: TargetsConfig) -> Targets {
        let settings = Settings::new(config.db.clone());
        Targets {
            db: config.db,
            audit: config.audit,
            scans: config.scans,
            backlog: config.backlog,
            purge: config.purge,
            encryption: config.encryption,
            settings,
            allowed_hosts: config.allowed_hosts,
            clock: config.clock,
            visibility: config.visibility,
        }
    }

    /// The orphan sweep (`purgeOrphanedTargetData`): **at every start**, as Java runs it on `ApplicationReadyEvent`,
    /// and on the hourly turn ([`OrphanedTargetRowsTask`]). Not a one-shot job: rows can be orphaned again by a repair
    /// run at the prompt, and the sweep costs one anti-join per table to find none.
    pub async fn purge_orphans(&self) -> Result<(), TargetError> {
        deletion::purge_orphans(&self.purge, &self.db).await
    }

    /// The registry the deletions publish to — for the composition test.
    pub fn purge_registry(&self) -> &PurgeRegistry {
        &self.purge
    }
}

/// `TargetSchedules.inForce` over a row's four columns and the installation's default, in minutes.
pub(crate) fn schedules_in_force(
    manual_only: bool,
    cron: Option<&str>,
    interval_minutes: Option<i32>,
    default_minutes: i64,
) -> InForce {
    schedules::in_force(manual_only, &crontab::parse(cron), interval_minutes, default_minutes)
}

/// The maintenance tasks this module contributes: `REPOSITORY_IDENTITIES` and `ORPHANED_TARGET_ROWS`.
pub fn tasks(targets: Arc<Targets>) -> Vec<Arc<dyn vectispire_cp_maintenance::MaintenanceTask>> {
    vec![Arc::new(RepositoryIdentityTask(targets.clone())), Arc::new(OrphanedTargetRowsTask(targets))]
}
