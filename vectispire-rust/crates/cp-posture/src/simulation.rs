//! `ScoreSimulationService` (experimental): every visible target's, project's and solution's score under the
//! production formula beside a candidate's, and how many targets read each grade under each — so that a change of
//! formula is decided on the estate's own figures. Grades nothing shown elsewhere, writes nothing.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;
use vectispire_cp_access::Allowance;
use vectispire_cp_access::rows::{ScopeKind, VisibleScope};
use vectispire_cp_db::ScanTarget;
use vectispire_cp_targets::{Targets, naming};
use vectispire_domain::java;

use crate::coverage;
use crate::error::PostureError;
use crate::scorecard::{CandidateScore, Counts, SecurityGrade, Weights};
use crate::scorecards::{SecurityScorecards, container_id, id_of, kind_of, repository_id};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreSimulationTarget {
    pub target_kind: String,
    pub target_id: i64,
    pub target_name: String,
    pub current_score: Option<i32>,
    pub current_grade: SecurityGrade,
    pub candidate_score: Option<i32>,
    pub candidate_grade: SecurityGrade,
    pub candidate_exact: Option<f64>,
    pub candidate_risk_points: Option<f64>,
    pub exploited: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub licences: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreSimulationWeakestTarget {
    pub target_kind: String,
    pub target_id: i64,
    pub target_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreSimulationScope {
    pub kind: String,
    pub id: i64,
    pub name: String,
    pub partial: bool,
    pub target_count: i32,
    pub observed_targets: i32,
    pub current_score: Option<i32>,
    pub current_grade: SecurityGrade,
    pub candidate_score: Option<i32>,
    pub candidate_grade: SecurityGrade,
    pub candidate_exact: Option<f64>,
    pub candidate_risk_points: Option<f64>,
    pub exploited: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub licences: i64,
    pub current_licences: i64,
    pub current_double_counted: bool,
    pub weakest_score: Option<i32>,
    pub weakest_grade: SecurityGrade,
    pub weakest_target: Option<ScoreSimulationWeakestTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScoreSimulationGrade {
    pub grade: SecurityGrade,
    pub current: i64,
    pub candidate: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScoreSimulation {
    pub weights: Weights,
    pub targets: Vec<ScoreSimulationTarget>,
    pub grades: Vec<ScoreSimulationGrade>,
    pub scopes: Vec<ScoreSimulationScope>,
}

/// The candidate's parameters as the route reads them: each absent one is the production formula's.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Requested {
    pub exploited: Option<f64>,
    pub critical: Option<f64>,
    pub high: Option<f64>,
    pub medium: Option<f64>,
    pub low: Option<f64>,
    pub licence: Option<f64>,
    pub k: Option<f64>,
}

#[derive(Clone)]
pub struct ScoreSimulations {
    scorecards: Arc<SecurityScorecards>,
    targets: Arc<Targets>,
    db: vectispire_cp_db::Db,
}

opaque_debug!(ScoreSimulations);

impl ScoreSimulations {
    pub fn new(
        scorecards: Arc<SecurityScorecards>,
        targets: Arc<Targets>,
        db: vectispire_cp_db::Db,
    ) -> ScoreSimulations {
        ScoreSimulations { scorecards, targets, db }
    }

    pub async fn simulate(&self, allowance: &Allowance, requested: Requested) -> Result<ScoreSimulation, PostureError> {
        let proposed = Weights::PROPOSED;
        let weights = Weights::new(
            requested.exploited.unwrap_or(proposed.exploited),
            requested.critical.unwrap_or(proposed.critical),
            requested.high.unwrap_or(proposed.high),
            requested.medium.unwrap_or(proposed.medium),
            requested.low.unwrap_or(proposed.low),
            requested.licence.unwrap_or(proposed.licence),
            requested.k.unwrap_or(proposed.k),
        )
        .map_err(PostureError::Invalid)?;

        let allowed = &allowance.visibility;
        let current = self.scorecards.grade_each(allowed).await?;
        let counts = self.scorecards.candidate_counts(allowed).await?;
        // Repositories, then images, each by id.
        let listed: Vec<ScanTarget> = current.keys().copied().collect();
        let names = naming::for_ids(
            &self.db,
            &listed.iter().filter_map(|target| repository_id(*target)).collect(),
            &listed.iter().filter_map(|target| container_id(*target)).collect(),
        )
        .await
        .map_err(PostureError::unexpected)?;

        let mut tally: BTreeMap<SecurityGrade, [i64; 2]> =
            SecurityGrade::ALL.iter().map(|grade| (*grade, [0, 0])).collect();
        let mut rows: Vec<(ScanTarget, ScoreSimulationTarget)> = Vec::new();
        for target in &listed {
            let Some(before) = current.get(target) else { continue };
            let open = counts.get(target).copied().unwrap_or(Counts::NONE);
            let no_data = before.grade == SecurityGrade::NoData;
            let after = (!no_data).then(|| CandidateScore::of(&open, &weights));
            let after_grade = after.map_or(SecurityGrade::NoData, |after| after.grade);
            if let Some([current, _]) = tally.get_mut(&before.grade) {
                *current = current.saturating_add(1);
            }
            if let Some([_, candidate]) = tally.get_mut(&after_grade) {
                *candidate = candidate.saturating_add(1);
            }
            let (repository, container) = (repository_id(*target), container_id(*target));
            rows.push((
                *target,
                ScoreSimulationTarget {
                    target_kind: kind_of(container).to_owned(),
                    target_id: id_of(*target),
                    target_name: names.of(repository, container),
                    current_score: before.score,
                    current_grade: before.grade,
                    candidate_score: after.map(|after| after.score),
                    candidate_grade: after_grade,
                    candidate_exact: after.map(|_| CandidateScore::exact(&open, &weights)),
                    candidate_risk_points: after.map(|after| after.risk_points),
                    exploited: open.exploited,
                    critical: open.critical,
                    high: open.high,
                    medium: open.medium,
                    low: open.low,
                    licences: open.licences,
                },
            ));
        }
        let grades = SecurityGrade::ALL
            .iter()
            .map(|grade| {
                let [current, candidate] = tally.get(grade).copied().unwrap_or_default();
                ScoreSimulationGrade { grade: *grade, current, candidate }
            })
            .collect();
        let scopes = self.scopes(allowance, &weights, &rows).await?;
        Ok(ScoreSimulation { weights, targets: rows.into_iter().map(|(_, row)| row).collect(), grades, scopes })
    }

    /// The scope's weakest observed target under the candidate: the lowest candidate score, then the more risk points;
    /// of two equal, the first listed.
    fn weakest_of<'a>(
        scope: &VisibleScope,
        rows: &'a [(ScanTarget, ScoreSimulationTarget)],
    ) -> Option<&'a ScoreSimulationTarget> {
        let mut weakest: Option<&ScoreSimulationTarget> = None;
        for (target, row) in rows {
            let Some(score) = row.candidate_score else { continue };
            if !scope.visible.contains(target) {
                continue;
            }
            let risk = row.candidate_risk_points.unwrap_or_default();
            let replaces = weakest.is_none_or(|current| {
                let current_score = current.candidate_score.unwrap_or(i32::MAX);
                score < current_score
                    || (score == current_score && risk > current.candidate_risk_points.unwrap_or_default())
            });
            if replaces {
                weakest = Some(row);
            }
        }
        weakest
    }

    async fn scopes(
        &self,
        allowance: &Allowance,
        weights: &Weights,
        rows: &[(ScanTarget, ScoreSimulationTarget)],
    ) -> Result<Vec<ScoreSimulationScope>, PostureError> {
        let visible = self.targets.visible_scopes(allowance).await.map_err(PostureError::unexpected)?;
        let mut scopes = Vec::new();
        for after in self.scorecards.candidate_scopes(&visible, weights).await? {
            let scope = &after.scope;
            let weakest = Self::weakest_of(scope, rows);
            // Held at the scope's observed share, as the sum is: one scanned clean target beside nine nobody looked at
            // is not an A+ under either.
            let weakest_score = weakest
                .and_then(|row| row.candidate_score)
                .map(|score| coverage::capped(score, after.total_targets, after.observed_targets));
            // The scope's card itself, as its compliance route serves it.
            let before = self.scorecards.scope_scorecard(scope).await?;
            let open = after.counts;
            scopes.push(ScoreSimulationScope {
                kind: match scope.kind {
                    ScopeKind::Project => "project",
                    ScopeKind::Solution => "solution",
                }
                .to_owned(),
                id: scope.id,
                name: scope.name.clone(),
                partial: scope.partial,
                target_count: after.total_targets,
                observed_targets: after.observed_targets,
                current_score: before.score,
                current_grade: before.grade,
                candidate_score: after.score,
                candidate_grade: after.grade,
                candidate_exact: after.exact,
                candidate_risk_points: after.risk_points,
                exploited: open.exploited,
                critical: open.critical,
                high: open.high,
                medium: open.medium,
                low: open.low,
                licences: open.licences,
                current_licences: before.license_violation_count,
                current_double_counted: before.license_violation_count != open.licences,
                weakest_score,
                weakest_grade: weakest_score.map_or(SecurityGrade::NoData, SecurityGrade::from_score),
                weakest_target: weakest.map(|row| ScoreSimulationWeakestTarget {
                    target_kind: row.target_kind.clone(),
                    target_id: row.target_id,
                    target_name: row.target_name.clone(),
                }),
            });
        }
        // Projects before solutions, then by name ignoring case (`toLowerCase(Locale.ROOT)`), then by id.
        scopes.sort_by(|a, b| {
            (a.kind == "solution")
                .cmp(&(b.kind == "solution"))
                .then_with(|| java::compare_utf16(&java::to_lower_root(&a.name), &java::to_lower_root(&b.name)))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(scopes)
    }
}
