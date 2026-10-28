//! Uploaded Semgrep rule sets: storing them, activating one, and serving them to executors.
//!
//! A port of `com.asmolabs.vectispire.core.rules`:
//! - Storage of rule files verbatim without YAML parsing (`ruleset`)
//! - Fetching upstream catalogue under explicit LGPL-2.1 with Commons Clause acceptance (`catalogue`)
//! - Static analysis rule coverage calculation across estate inventory ecosystems (`coverage`)
//! - Triage impact analysis before activating or deactivating rule sets (`ruleset::impact`)
//! - Audited administrative management (`RuleSetAdministrationService`)
//! - Port implementation of `ScanRuleSets` for scanning executors (`RuleSetsForScans`)

#![forbid(unsafe_code)]

pub mod catalogue;
pub mod coverage;
mod internal;
mod persistence;
pub mod ports;
pub mod ruleset;
mod service;
mod web;

use std::sync::Arc;

use vectispire_cp_audit::AuditLog;
use vectispire_cp_db::Db;
use vectispire_cp_http::routes::RouteEntry;
use vectispire_cp_scanning::ports::ScanRuleSets;

pub use catalogue::RuleCatalogueFetcher;
pub use coverage::Assessment;
pub use internal::RuleSetsForScans;
pub use persistence::{NewSemgrepRuleSet, SemgrepRuleSetRecord, SemgrepRuleSetRepository, SemgrepRuleSetSummary};
pub use ports::{InventoryEcosystems, IssueRuleCounts, StandInInventory, StandInIssues};
pub use ruleset::{StoredFile, TriageImpact, UploadedFile};
pub use service::{
    RuleCoverageService, RuleSetAdministrationService, RuleSetListing, RuleSetService,
    RuleSetSummary as ServiceRuleSetSummary, RuleSetView, ServiceError,
};

/// Combined composition of the `rules` module services.
#[derive(Clone)]
pub struct RulesModule {
    pub admin: Arc<RuleSetAdministrationService>,
    pub coverage: Arc<RuleCoverageService>,
    pub rules_service: Arc<RuleSetService>,
    pub for_scans: Arc<RuleSetsForScans>,
}

impl std::fmt::Debug for RulesModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RulesModule").finish_non_exhaustive()
    }
}

impl RulesModule {
    pub fn new(
        db: Db,
        inventory: Arc<dyn InventoryEcosystems>,
        issues: Arc<dyn IssueRuleCounts>,
        audit: Arc<AuditLog>,
    ) -> Self {
        let repo = Arc::new(SemgrepRuleSetRepository::new(db));
        let rules_service = Arc::new(RuleSetService::new(repo.clone(), issues));
        let fetcher = RuleCatalogueFetcher::new();
        let admin = Arc::new(RuleSetAdministrationService::new((*rules_service).clone(), fetcher, audit));
        let coverage = Arc::new(RuleCoverageService::new((*rules_service).clone(), inventory));
        let for_scans = Arc::new(RuleSetsForScans::new(repo));

        Self { admin, coverage, rules_service, for_scans }
    }

    /// The `ScanRuleSets` port implementation for `cp-scanning` and executors.
    pub fn scan_rule_sets(&self) -> Arc<dyn ScanRuleSets> {
        self.for_scans.clone()
    }

    /// The HTTP routes exposed by `RuleSetsController`.
    pub fn routes(&self) -> Vec<RouteEntry> {
        web::routes(self.admin.clone(), self.coverage.clone())
    }
}
