//! The control plane's issues module: backlog, triage, fingerprint reconciliation, history and exceptions register.

#![forbid(unsafe_code)]

/// `Debug` for a type whose fields are services and pools: the name alone, since a pool's contents say
/// nothing useful in a log and the workspace denies `missing_debug_implementations`.
macro_rules! opaque_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    )+};
}

pub mod catalog;
pub mod decision;
pub mod error;
pub mod exceptions;
pub mod history;
mod persistence;
pub use persistence::{IssueFilters, Lifetime, StoreError};
pub mod purge;
pub mod queries;
pub mod query;
pub mod sla;
pub mod sync;
pub mod target_backlog;
pub mod triage;
pub mod views;

mod internal;
mod web;

use std::sync::Arc;

use vectispire_cp_audit::AuditLog;
use vectispire_cp_db::Db;
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::Targets;

pub use catalog::IssueCatalog;
pub use decision::{Caller, Decision, IssueDecisionService};
pub use error::IssueError;
pub use exceptions::{ExceptionEntry, ExceptionReviewService, ExceptionsRegisterService, Register};
pub use history::{Dossier, HistoryQueryService, ObservedIssue, TriageHistoryRepository, TriageHistoryScan};
pub use purge::listeners;
pub use query::{BacklogQuery, IssueQueryService};
pub use sla::{RemediationSla, SlaBreachSignals, SlaService};
pub use sync::{IssueBacklog, IssueSyncService};
pub use target_backlog::TargetBacklogFigures;
pub use triage::{
    IssueTriageService, ReviewOutcome, Triage, TriageDecision, TriageOrigin, TriageRequest, TriageStatus,
    VexJustification,
};
pub use views::{BacklogEntry, DecisionView, IssueDetail, IssuePage, IssueView, Sighting};

pub use internal::{SlaBreachTask, TriageExpiryTask};
pub use web::routes;

/// Configuration for creating the [`Issues`] module.
#[derive(Clone)]
pub struct IssuesConfig {
    pub db: Db,
    pub targets: Arc<Targets>,
    pub scans: ScanCatalog,
    pub settings: Arc<Settings>,
    pub audit: Arc<AuditLog>,
}

/// The issues module facade bundling all sub-services and adapters.
#[derive(Clone)]
pub struct Issues {
    db: Db,
    queries: Arc<IssueQueryService>,
    decisions: Arc<IssueDecisionService>,
    history: Arc<HistoryQueryService>,
    exceptions: Arc<ExceptionsRegisterService>,
    reviews: Arc<ExceptionReviewService>,
    catalog: Arc<IssueCatalog>,
    triage: Arc<IssueTriageService>,
    sla: Arc<SlaService>,
    breaches: Arc<SlaBreachSignals>,
    backlog: Arc<IssueBacklog>,
    target_backlog: Arc<TargetBacklogFigures>,
}

impl Issues {
    pub fn new(config: IssuesConfig) -> Self {
        let sla = Arc::new(SlaService::new(config.db.clone(), config.settings.clone()));
        let breaches = Arc::new(SlaBreachSignals::new(config.db.clone(), sla.clone()));
        let triage = Arc::new(IssueTriageService::new(config.db.clone()));
        let queries = Arc::new(IssueQueryService::new(
            config.db.clone(),
            config.targets.clone(),
            config.scans.clone(),
            (*sla).clone(),
        ));
        let decisions =
            Arc::new(IssueDecisionService::new(config.db.clone(), config.settings.clone(), config.audit.clone()));
        let history =
            Arc::new(HistoryQueryService::new(config.db.clone(), config.targets.clone(), config.scans.clone()));
        let exceptions = Arc::new(ExceptionsRegisterService::new(config.db.clone()));
        let reviews =
            Arc::new(ExceptionReviewService::new(config.db.clone(), (*triage).clone(), (*exceptions).clone()));
        let catalog = Arc::new(IssueCatalog::new(config.db.clone()));
        let backlog = Arc::new(IssueBacklog::new(config.db.clone()));
        let target_backlog = Arc::new(TargetBacklogFigures::new(config.db.clone()));

        Self {
            db: config.db,
            queries,
            decisions,
            history,
            exceptions,
            reviews,
            catalog,
            triage,
            sla,
            breaches,
            backlog,
            target_backlog,
        }
    }

    pub fn queries(&self) -> &Arc<IssueQueryService> {
        &self.queries
    }

    pub fn decisions(&self) -> &Arc<IssueDecisionService> {
        &self.decisions
    }

    pub fn history(&self) -> &Arc<HistoryQueryService> {
        &self.history
    }

    pub fn exceptions(&self) -> &Arc<ExceptionsRegisterService> {
        &self.exceptions
    }

    pub fn reviews(&self) -> &Arc<ExceptionReviewService> {
        &self.reviews
    }

    pub fn catalog(&self) -> &Arc<IssueCatalog> {
        &self.catalog
    }

    pub fn triage(&self) -> &Arc<IssueTriageService> {
        &self.triage
    }

    pub fn sla(&self) -> &Arc<SlaService> {
        &self.sla
    }

    pub fn breaches(&self) -> &Arc<SlaBreachSignals> {
        &self.breaches
    }

    pub fn backlog(&self) -> &Arc<IssueBacklog> {
        &self.backlog
    }

    pub fn target_backlog(&self) -> &Arc<TargetBacklogFigures> {
        &self.target_backlog
    }

    pub fn db(&self) -> &Db {
        &self.db
    }
}

/// The maintenance tasks this module contributes: [`TriageExpiryTask`] and [`SlaBreachTask`].
pub fn tasks(issues: Arc<Issues>) -> Vec<Arc<dyn vectispire_cp_maintenance::MaintenanceTask>> {
    vec![
        Arc::new(internal::TriageExpiryTask::new(issues.triage().clone())),
        Arc::new(internal::SlaBreachTask::new(issues.breaches().clone())),
    ]
}

opaque_debug!(IssuesConfig, Issues);
