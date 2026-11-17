//! A project's or a solution's compliance — Java's `ScopeComplianceService`: the matrix over the scope's visible
//! targets, with the scope's scorecard beside it.

use std::sync::Arc;

use serde::Serialize;
use vectispire_cp_access::Allowance;
use vectispire_cp_access::rows::{ScopeKind, VisibleScope};
use vectispire_cp_db::Visibility;
use vectispire_cp_posture::scorecard::SecurityScorecard;
use vectispire_cp_posture::scorecards::SecurityScorecards;
use vectispire_cp_targets::Targets;

use crate::error::ComplianceError;
use crate::matrix::{ComplianceService, ComplianceSummary};

/// `ScopeCompliance`, members in the record's order.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeCompliance {
    pub kind: &'static str,
    pub id: i64,
    pub name: String,
    pub partial: bool,
    pub target_count: usize,
    pub compliance: ComplianceSummary,
    pub scorecard: SecurityScorecard,
}

#[derive(Clone)]
pub struct ScopeComplianceService {
    targets: Arc<Targets>,
    compliance: ComplianceService,
    scorecards: Arc<SecurityScorecards>,
}

impl std::fmt::Debug for ScopeComplianceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ScopeComplianceService").finish_non_exhaustive()
    }
}

impl ScopeComplianceService {
    pub fn new(
        targets: Arc<Targets>,
        compliance: ComplianceService,
        scorecards: Arc<SecurityScorecards>,
    ) -> ScopeComplianceService {
        ScopeComplianceService { targets, compliance, scorecards }
    }

    /// "Project not found." for a project that does not exist and one the caller sees nothing of.
    pub async fn of_project(&self, id: i64, allowance: &Allowance) -> Result<ScopeCompliance, ComplianceError> {
        let scope = self.targets.visible_project(id, allowance).await.map_err(refusal)?;
        self.of(scope).await
    }

    /// "Solution not found." for a solution that does not exist and one the caller sees nothing of.
    pub async fn of_solution(&self, id: i64, allowance: &Allowance) -> Result<ScopeCompliance, ComplianceError> {
        let scope = self.targets.visible_solution(id, allowance).await.map_err(refusal)?;
        self.of(scope).await
    }

    async fn of(&self, scope: VisibleScope) -> Result<ScopeCompliance, ComplianceError> {
        let visibility = Visibility::Only(scope.visible.iter().copied().collect());
        let compliance = self.compliance.summary(&visibility).await?;
        let scorecard = self.scorecards.scope_scorecard(&scope).await.map_err(ComplianceError::unexpected)?;
        Ok(ScopeCompliance {
            kind: match scope.kind {
                ScopeKind::Project => "project",
                ScopeKind::Solution => "solution",
            },
            id: scope.id,
            name: scope.name,
            partial: scope.partial,
            target_count: scope.visible.len(),
            compliance,
            scorecard,
        })
    }
}

/// The scope's refusal as it is — a 404 carrying the guard's sentence — and anything else unexpected.
fn refusal(error: vectispire_cp_targets::TargetError) -> ComplianceError {
    match error {
        vectispire_cp_targets::TargetError::NotFound(message) => ComplianceError::NotFound(message),
        other => ComplianceError::unexpected(other),
    }
}
