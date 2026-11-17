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
pub mod engine;
pub mod error;
pub mod framework;
pub mod history;
pub mod instant_text;
mod internal;
pub mod manifest;
pub mod matrix;
pub mod scope_coverage;
pub mod soa;
// The statements stages 2 to 4 serve (the statement of applicability, the history, the weekly record, the report) are
// written and tested ahead of their services; `expect` and not `allow`, so the attribute fails the build the day they
// are all in use and has to go.
#[expect(dead_code, reason = "the repositories of the routes still to port, tested ahead of their services")]
mod persistence;
pub mod ports;
pub mod purge;
pub mod scope;

pub use web::{Services, routes};
mod web;

use std::sync::Arc;

use vectispire_cp_db::Db;
use vectispire_cp_maintenance::MaintenanceTask;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::Clock;

/// The module's maintenance tasks so far: the evidence window of the snapshots and of the weekly OWASP record, and the
/// abandoned reports. The history's capture and the weekly record's come with their services.
pub fn tasks(db: Db, settings: Settings, clock: Arc<dyn Clock>) -> Vec<Arc<dyn MaintenanceTask>> {
    vec![
        Arc::new(internal::tasks::SnapshotRetentionTask::new(db.clone(), settings.clone(), clock.clone())),
        Arc::new(internal::tasks::WeeklyRetentionTask::new(db.clone(), settings, clock.clone())),
        Arc::new(internal::tasks::AbandonedReviewsTask::new(db, clock)),
    ]
}
