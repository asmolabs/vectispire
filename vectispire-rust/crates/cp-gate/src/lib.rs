//! `vectispire-cp-gate`
//! Quality Gate policy enforcement, CI/CD build verdicts, and verdict register.

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

pub mod cursor;
pub mod error;
pub mod fields;
pub mod flag;
pub mod gate;
mod internal;
pub mod issue;
pub mod observation;
pub mod overview;
mod persistence;
pub mod policy;
pub mod purge;
pub mod resolution;
pub mod service;
pub mod verdict;
mod web;

use std::sync::Arc;

use vectispire_cp_audit::AuditLog;
use vectispire_cp_db::Db;
use vectispire_cp_http::routes::RouteEntry;
use vectispire_cp_issues::IssueCatalog;
use vectispire_cp_maintenance::MaintenanceTask;
use vectispire_cp_rules::RuleCoverageService;
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::{Clock, Targets};

pub use vectispire_cp_db::ScanTarget;

pub use error::GateError;
pub use fields::GatePolicyFields;
pub use flag::PolicyFlag;
pub use gate::{Hardened, PolicyGate};
pub use internal::VerdictRetentionTask;
pub use issue::GateIssue;
pub use observation::Observation;
pub use overview::{LatestScan, NamedTarget, Overview, SecurityOverview, TargetPosture};
pub use policy::GatePolicy;
pub use purge::{GatePolicyPurge, listeners};
pub use resolution::{
    PolicyLookup, PolicyResolution, PolicyScopeChoice, PolicySource, RequestedPolicy, ResolvedPolicy, SeverityRequest,
    StoredPolicy,
};
pub use service::{
    ActiveGatePolicies, Caller, Decision, GatePolicyAdministrationService, GateRegisterService, GateService,
    GateVerdictView, PolicyScope, RegisterPage, RegisteredVerdictItem, StoredGatePolicyView,
};
pub use verdict::{Coverage, GateVerdict, Rule, Violation};
pub use web::routes;
pub use web::views::*;

/// The composed Gate module.
pub struct GateModule {
    pub gate: Arc<GateService>,
    pub admin: Arc<GatePolicyAdministrationService>,
    pub verdicts: Arc<GateRegisterService>,
}

opaque_debug!(GateModule);

impl GateModule {
    pub fn new(
        db: Db,
        issues: Arc<IssueCatalog>,
        scans: Arc<ScanCatalog>,
        targets: Arc<Targets>,
        coverage: Arc<RuleCoverageService>,
        audit: Arc<AuditLog>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let gate = Arc::new(GateService::new(db.clone(), issues, scans, targets, coverage, clock));
        let admin = Arc::new(GatePolicyAdministrationService::new(gate.clone(), audit));
        let verdicts = Arc::new(GateRegisterService::new(db));
        Self { gate, admin, verdicts }
    }

    pub fn routes(&self) -> Vec<RouteEntry> {
        web::routes(self.gate.clone(), self.admin.clone(), self.verdicts.clone())
    }

    pub fn tasks(&self, settings: Settings, clock: Arc<dyn Clock>) -> Vec<Arc<dyn MaintenanceTask>> {
        vec![Arc::new(VerdictRetentionTask::new(self.gate.db().clone(), settings, clock))]
    }
}

pub fn tasks(db: Db, settings: Settings, clock: Arc<dyn Clock>) -> Vec<Arc<dyn MaintenanceTask>> {
    vec![Arc::new(VerdictRetentionTask::new(db, settings, clock))]
}
