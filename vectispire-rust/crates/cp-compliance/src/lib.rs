//! Compliance — Java's `core/compliance`: the framework matrix and its per-scope reading, the statement of
//! applicability, the certified scope, the monthly history, the OWASP Top 10 grid with its weekly record, and the
//! OWASP report. The pure decisions are [`decisions`] and `vectispire_domain::owasp_coverage`; this crate holds what
//! reads and writes, in the module layout every ported module keeps (`persistence` beneath the services).

#![forbid(unsafe_code)]

/// The pure compliance domain — Java's `vectispire-common` `domain/compliance`: the six frameworks and their
/// controls, the engine that evaluates them from an estate and a platform, the declaration of applicability set
/// against its verdicts, the attributed monthly history, the certified scope's gap and the evidence bundle's manifest
/// (the root files `framework`, `engine`, `soa`, `history`, `scope_coverage`, `manifest`).
///
/// Held to `reference/compliance/`, which `ComplianceReferenceSetTest` writes from the Java classes. **Here and not in
/// `vectispire-domain`**: the agent links that crate, and a sentence of the engine names the encryption key, which
/// nothing the agent links may (`cp-arch-tests`' isolation) — and nothing of compliance is the agent's.
pub mod decisions {
    pub use crate::engine::{
        ComplianceEvaluation, ControlAssessment, PasswordAccounts, PlatformPosture, PostureInput, evaluate,
        evaluate_all,
    };
    pub use crate::framework::{Category, ComplianceControl, ComplianceFramework, Status, UnknownFramework};
    pub use crate::history::{ComplianceSnapshot, Movement, Series, Shape, Step};
    pub use crate::manifest::{EvidenceBundleManifest, EvidenceFileEntry, WithheldSection};
    pub use crate::scope_coverage::ScopeCoverage;
    pub use crate::soa::{
        Applicability, Declaration, Divergence, EvidenceSource, Implementation, Line, SoaStatement, reconcile,
    };
    pub use crate::{engine, framework, history, instant_text, manifest, soa};
}
pub mod certified;
pub mod coverage;
pub mod declarations;
pub mod engine;
pub mod error;
pub mod framework;
pub mod grid;
pub mod history;
pub mod instant_text;
mod internal;
pub mod manifest;
pub mod markdown;
pub mod matrix;
pub mod owasp_words;
pub mod scope_coverage;
pub mod soa;
pub mod weekly;
pub mod weekly_capture;
// The statements stages 2 to 4 serve (the statement of applicability, the history, the weekly record, the report) are
// written and tested ahead of their services; `expect` and not `allow`, so the attribute fails the build the day they
// are all in use and has to go.
#[expect(dead_code, reason = "the repositories of the routes still to port, tested ahead of their services")]
mod persistence;
pub mod ports;
pub mod progress;
pub mod purge;
pub mod review;
pub mod scope;

pub use web::{Services, routes};
mod web;

use std::sync::Arc;

use vectispire_cp_db::Db;
use vectispire_cp_maintenance::MaintenanceTask;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::Clock;

/// The module's maintenance tasks: the month's captures and the week's OWASP record, the evidence window of both,
/// and the abandoned reports.
pub fn tasks(db: Db, settings: Settings, clock: Arc<dyn Clock>, services: &Services) -> Vec<Arc<dyn MaintenanceTask>> {
    vec![
        Arc::new(internal::tasks::ComplianceHistoryTask(services.history.clone())),
        Arc::new(internal::tasks::OwaspWeeklyCoverageTask(services.weekly_capture.clone())),
        Arc::new(internal::tasks::SnapshotRetentionTask::new(db.clone(), settings.clone(), clock.clone())),
        Arc::new(internal::tasks::WeeklyRetentionTask::new(db.clone(), settings, clock.clone())),
        Arc::new(internal::tasks::AbandonedReviewsTask::new(db, clock)),
    ]
}

impl Services {
    /// The matrix and the scopes as composed, and the governance and the OWASP grid over the same estate.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        compliance: matrix::ComplianceService,
        scopes: scope::ScopeComplianceService,
        db: vectispire_cp_db::Db,
        targets: Arc<vectispire_cp_targets::Targets>,
        scans: Arc<vectispire_cp_scanning::ScanCatalog>,
        issues: Arc<vectispire_cp_issues::queries::IssueCatalog>,
        backlog: Arc<vectispire_cp_issues::IssueQueryService>,
        rules: Arc<vectispire_cp_rules::RuleCoverageService>,
        settings: vectispire_cp_settings::Settings,
        audit: Arc<vectispire_cp_audit::AuditLog>,
        clock: Arc<dyn vectispire_cp_targets::Clock>,
    ) -> Services {
        let soa = declarations::StatementOfApplicabilityService::new(
            db.clone(),
            compliance.clone(),
            audit.clone(),
            clock.clone(),
        );
        let coverage = coverage::OwaspCoverageService::new(
            issues.clone(),
            scans.clone(),
            targets.clone(),
            rules,
            settings.clone(),
        );
        Services {
            report: review::OwaspReportService::new(
                db.clone(),
                targets.clone(),
                backlog,
                issues.clone(),
                clock.clone(),
            ),
            certified: certified::CertifiedScopeService::new(targets, scans, settings.clone(), clock.clone(), audit),
            history: progress::ComplianceHistoryService::capturing(
                db.clone(),
                compliance.clone(),
                soa.clone(),
                coverage.clone(),
                settings,
                clock.clone(),
            ),
            grid: grid::OwaspGridService::new(coverage.clone(), soa.clone()),
            weekly: weekly::OwaspWeeklyHistoryService::new(db.clone(), issues, coverage.clone(), clock.clone()),
            weekly_capture: weekly_capture::OwaspWeeklyCoverageService::new(db, coverage, clock),
            soa,
            compliance,
            scopes,
        }
    }
}
