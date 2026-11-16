//! `SecurityScorecardService`: the cards of a repository, an image, a project or a solution, the portfolio's
//! distribution, and each target's grade for the ranking — **one computation**, [`SecurityScorecards::card`], which
//! every screen and the public badge read, so that one target reads one grade everywhere.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use vectispire_cp_access::rows::{self, ScopeKind, VisibleScope};
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_inventory::LicenseGovernanceService;
use vectispire_cp_issues::queries::TargetGradingCount;
use vectispire_cp_issues::{IssueCatalog, IssueFilters, SlaService};
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_targets::{Targets, naming};
use vectispire_domain::java;

use crate::coverage::{self, Coverage};
use crate::error::PostureError;
use crate::scorecard::{
    CandidateScore, Counts, GradeCount, PortfolioScorecard, ScoreResult, SecurityGrade, SecurityScorecard,
    WeakestTarget, Weights,
};

/// The weights every grade is computed with.
pub const WEIGHTS: Weights = Weights::PROPOSED;

/// The scan status that makes a target observed.
const COMPLETED: &str = "completed";

/// A target's score and grade as its own card gives them, and the open counts a ranking prints beside them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TargetGrade {
    pub score: Option<i32>,
    pub grade: SecurityGrade,
    pub risk_points: Option<f64>,
    pub critical: i64,
    pub high: i64,
    /// An issue with no severity is counted here, and weighs as a medium.
    pub medium: i64,
    pub low: i64,
}

impl TargetGrade {
    /// A target listed for what it closed, holding no completed scan and nothing open.
    pub const UNOBSERVED: TargetGrade = TargetGrade {
        score: None,
        grade: SecurityGrade::NoData,
        risk_points: None,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };
}

/// The open backlog counted twice over the same rows: as the card shows it (KEV also under its severity) and as the
/// formula weighs it (an exploited issue in its own class only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Terms {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub kev: i64,
    weighed: [i64; 5],
}

impl Terms {
    /// Open when neither `closed` nor `resolved`, ignoring case — a missing state included.
    fn is_open(state: &str) -> bool {
        !state.eq_ignore_ascii_case("closed") && !state.eq_ignore_ascii_case("resolved")
    }

    pub(crate) fn of<'a>(rows: impl IntoIterator<Item = &'a TargetGradingCount>) -> Terms {
        fn add(slots: &mut [i64; 5], slot: usize, count: i64) {
            if let Some(total) = slots.get_mut(slot) {
                *total = total.saturating_add(count);
            }
        }
        let mut shown = [0i64; 5];
        let mut weighed = [0i64; 5];
        for row in rows {
            if !Self::is_open(&row.state) {
                continue;
            }
            let severity = row.severity.as_deref().map(java::to_upper_root);
            let slot = match severity.as_deref() {
                Some("CRITICAL") => 0,
                Some("HIGH") => 1,
                None | Some("MEDIUM") => 2,
                Some(_) => 3,
            };
            add(&mut shown, slot, row.c);
            if row.is_kev {
                add(&mut shown, 4, row.c);
                add(&mut weighed, 4, row.c);
            } else {
                add(&mut weighed, slot, row.c);
            }
        }
        let [critical, high, medium, low, kev] = shown;
        Terms { critical, high, medium, low, kev, weighed }
    }

    /// The formula's classes, with the licence count the card charges.
    pub(crate) fn weighed(&self, licences: i64) -> Counts {
        let [critical, high, medium, low, exploited] = self.weighed;
        Counts { exploited, critical, high, medium, low, licences }
    }
}

/// `ScanTarget.ofColumns`: a row naming a repository is its repository's; one naming neither ranks nowhere.
pub(crate) fn target_of(repository: Option<i64>, container: Option<i64>) -> Option<ScanTarget> {
    match (repository, container) {
        (Some(id), _) => Some(ScanTarget::Repository(id)),
        (None, Some(id)) => Some(ScanTarget::Container(id)),
        (None, None) => None,
    }
}

pub(crate) fn id_of(target: ScanTarget) -> i64 {
    match target {
        ScanTarget::Repository(id) | ScanTarget::Container(id) => id,
    }
}

pub(crate) fn repository_id(target: ScanTarget) -> Option<i64> {
    match target {
        ScanTarget::Repository(id) => Some(id),
        ScanTarget::Container(_) => None,
    }
}

pub(crate) fn container_id(target: ScanTarget) -> Option<i64> {
    match target {
        ScanTarget::Container(id) => Some(id),
        ScanTarget::Repository(_) => None,
    }
}

/// `Names.kindOf`.
pub(crate) fn kind_of(container: Option<i64>) -> &'static str {
    if container.is_some() { "container" } else { "repository" }
}

/// Every issue the caller may see that still weighs on the grade: open in any state but closed or resolved (the test
/// is in [`Terms`]), a settled triage left out as the gate leaves it out.
pub(crate) fn open_within(allowed: Visibility) -> IssueFilters {
    IssueFilters { state: None, exclude_settled: true, ..IssueFilters::new(allowed) }
}

/// The open rows, each under the one target the ranking files it under.
fn by_target(rows: &[TargetGradingCount]) -> BTreeMap<ScanTarget, Terms> {
    let mut grouped: BTreeMap<ScanTarget, Vec<&TargetGradingCount>> = BTreeMap::new();
    for row in rows {
        if let Some(target) = target_of(row.repo_id, row.container_id)
            && Terms::is_open(&row.state)
        {
            grouped.entry(target).or_default().push(row);
        }
    }
    grouped.into_iter().map(|(target, rows)| (target, Terms::of(rows))).collect()
}

/// Of two graded results, whether `candidate` is the weaker: the lower score, then the more risk points. Neither: the
/// first one listed stays.
fn weaker(candidate: &ScoreResult, current: &ScoreResult) -> bool {
    candidate.score < current.score || (candidate.score == current.score && candidate.risk_points > current.risk_points)
}

/// Each target's grade, and the whole allowance's open backlog read from the same rows.
struct Graded {
    grades: BTreeMap<ScanTarget, TargetGrade>,
    whole: Terms,
}

/// A project or a solution under the formula over its summed backlog, for the simulation only.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopeCandidate {
    pub scope: VisibleScope,
    pub counts: Counts,
    pub total_targets: i32,
    pub observed_targets: i32,
    pub score: Option<i32>,
    pub grade: SecurityGrade,
    pub exact: Option<f64>,
    pub risk_points: Option<f64>,
}

#[derive(Clone)]
pub struct SecurityScorecards {
    db: Db,
    issues: Arc<IssueCatalog>,
    sla: Arc<SlaService>,
    scans: Arc<ScanCatalog>,
    targets: Arc<Targets>,
    licences: Arc<LicenseGovernanceService>,
}

opaque_debug!(SecurityScorecards);

impl SecurityScorecards {
    pub fn new(
        db: Db,
        issues: Arc<IssueCatalog>,
        sla: Arc<SlaService>,
        scans: Arc<ScanCatalog>,
        targets: Arc<Targets>,
        licences: Arc<LicenseGovernanceService>,
    ) -> SecurityScorecards {
        SecurityScorecards { db, issues, sla, scans, targets, licences }
    }

    /// A repository's card, for a caller who may see it — refused as a hidden target **before the row is read**, so no
    /// lookup tells it from an absent one; an absent one the caller could see is `None`.
    pub async fn repository_scorecard(
        &self,
        repository: i64,
        allowed: &Visibility,
    ) -> Result<Option<SecurityScorecard>, PostureError> {
        let target = ScanTarget::Repository(repository);
        rows::require_visible(target, allowed)?;
        let Some(found) = self.targets.catalog_repository(repository).await.map_err(PostureError::unexpected)? else {
            return Ok(None);
        };
        // `repo.name()`: the repository's own name, absent when the operator never chose one.
        Ok(Some(self.target_card(target, "repository", found.name, allowed).await?))
    }

    /// An image's card, refused as [`Self::repository_scorecard`] is.
    pub async fn container_scorecard(
        &self,
        container: i64,
        allowed: &Visibility,
    ) -> Result<Option<SecurityScorecard>, PostureError> {
        let target = ScanTarget::Container(container);
        rows::require_visible(target, allowed)?;
        let Some(found) = self.targets.catalog_container(container).await.map_err(PostureError::unexpected)? else {
            return Ok(None);
        };
        let name = format!("{}:{}", found.image_name, found.tag);
        Ok(Some(self.target_card(target, "container", Some(name), allowed).await?))
    }

    async fn target_card(
        &self,
        target: ScanTarget,
        kind: &str,
        name: Option<String>,
        allowed: &Visibility,
    ) -> Result<SecurityScorecard, PostureError> {
        let only = Visibility::Only(BTreeSet::from([target]));
        // The read narrowed to this target, not the estate filtered down to it afterwards.
        let rows = self
            .issues
            .count_for_grading_by_target(&open_within(only.clone()))
            .await
            .map_err(PostureError::unexpected)?;
        let open = Terms::of(&rows);
        let (repository, container) = (repository_id(target), container_id(target));
        let licences = self
            .licences
            .get_inventory(allowed, repository, container, None, None)
            .await
            .map_err(PostureError::unexpected)?
            .iter()
            .filter(|entry| entry.target_id == Some(id_of(target)) && entry.target_kind.eq_ignore_ascii_case(kind))
            .filter(|entry| !entry.compliant)
            .count();
        let licences = i64::try_from(licences).unwrap_or(i64::MAX);
        let attested = self.scans.has_scan_with_status(target, COMPLETED).await.map_err(PostureError::unexpected)?;
        let overdue = self.sla.count_overdue(&only).await.map_err(PostureError::unexpected)?;
        let score = CandidateScore::of(&open.weighed(licences), &WEIGHTS).score;
        Ok(Self::card(
            Some(id_of(target)),
            Some(kind.to_owned()),
            name,
            &open,
            licences,
            attested,
            overdue,
            Coverage::of_one(attested),
            Some(score),
            None,
        ))
    }

    /// The portfolio within the caller's allowance: how many targets read each grade, the weakest, and the risk points
    /// of everything open — no grade of its own (decision 0036).
    pub async fn portfolio_scorecard(&self, allowed: &Visibility) -> Result<PortfolioScorecard, PostureError> {
        let repositories = self.targets.catalog_repositories().await.map_err(PostureError::unexpected)?;
        let containers = self.targets.catalog_containers().await.map_err(PostureError::unexpected)?;
        // Repositories, then images, each by id: `ScanTarget`'s order.
        let visible: BTreeSet<ScanTarget> = repositories
            .iter()
            .map(|repository| ScanTarget::Repository(repository.id))
            .chain(containers.iter().map(|container| ScanTarget::Container(container.id)))
            .filter(|target| allowed.permits(*target))
            .collect();

        let violations = self.licences.violations(allowed).await.map_err(PostureError::unexpected)?;
        let graded = self.grade(allowed, &violations.by_target).await?;
        let mut distribution: BTreeMap<SecurityGrade, i64> =
            SecurityGrade::ALL.iter().map(|grade| (*grade, 0)).collect();
        // Over the targets the reader sees, never over the graded map's keys: a row is keyed to its repository even
        // when the reader was given only the image it also names.
        let mut weakest: Option<(ScanTarget, TargetGrade)> = None;
        let mut observed: i32 = 0;
        for target in &visible {
            let grade = graded.grades.get(target).copied().unwrap_or(TargetGrade::UNOBSERVED);
            let tally = distribution.entry(grade.grade).or_default();
            *tally = tally.saturating_add(1);
            let (Some(score), Some(risk)) = (grade.score, grade.risk_points) else { continue };
            observed = observed.saturating_add(1);
            let replaces = weakest.as_ref().is_none_or(|(_, current)| {
                let (current_score, current_risk) =
                    (current.score.unwrap_or(i32::MAX), current.risk_points.unwrap_or(0.0));
                score < current_score || (score == current_score && risk > current_risk)
            });
            if replaces {
                weakest = Some((*target, grade));
            }
        }

        let licences = violations.total;
        let open = graded.whole;
        let weakest_target = match weakest {
            Some((target, grade)) => {
                Some(self.named(target, grade.score.unwrap_or_default(), grade.risk_points.unwrap_or_default()).await?)
            }
            None => None,
        };
        Ok(PortfolioScorecard {
            total_targets: i32::try_from(visible.len()).unwrap_or(i32::MAX),
            observed_targets: observed,
            grades: SecurityGrade::ALL
                .iter()
                .map(|grade| GradeCount {
                    grade: *grade,
                    targets: distribution.get(grade).copied().unwrap_or_default(),
                })
                .collect(),
            weakest_target,
            risk_points: CandidateScore::risk_points(&open.weighed(licences), &WEIGHTS),
            open_critical_count: open.critical,
            open_high_count: open.high,
            open_kev_count: open.kev,
            overdue_count: self.sla.count_overdue(allowed).await.map_err(PostureError::unexpected)?,
            license_violation_count: licences,
        })
    }

    /// A project's or a solution's card, over the scope's visible targets, **graded by its weakest link**: the lowest
    /// score among its observed targets, each as its own card computes it, held at the scope's observed share.
    pub async fn scope_scorecard(&self, scope: &VisibleScope) -> Result<SecurityScorecard, PostureError> {
        let allowed = Visibility::Only(scope.visible.iter().copied().collect());
        let rows = self
            .issues
            .count_for_grading_by_target(&open_within(allowed.clone()))
            .await
            .map_err(PostureError::unexpected)?;
        let terms_by_target = by_target(&rows);
        let violations = self.licences.violations(&allowed).await.map_err(PostureError::unexpected)?.by_target;
        let observed = self.completed_among(&scope.visible.iter().copied().collect()).await?;

        let mut weakest: Option<(ScanTarget, ScoreResult)> = None;
        let mut licences: i64 = 0;
        for target in &scope.visible {
            let refused = violations.get(target).copied().unwrap_or_default();
            licences = licences.saturating_add(refused);
            // A target never scanned has no grade of its own to lend the scope; its issues are in the risk points.
            if !observed.contains(target) {
                continue;
            }
            let terms = terms_by_target.get(target).copied().unwrap_or_default();
            let result = CandidateScore::of(&terms.weighed(refused), &WEIGHTS);
            if weakest.as_ref().is_none_or(|(_, current)| weaker(&result, current)) {
                weakest = Some((*target, result));
            }
        }
        let named = match weakest {
            Some((target, result)) => Some(self.named(target, result.score, result.risk_points).await?),
            None => None,
        };
        let kind = match scope.kind {
            ScopeKind::Project => "project",
            ScopeKind::Solution => "solution",
        };
        let total = i32::try_from(scope.visible.len()).unwrap_or(i32::MAX);
        let observed_count = i32::try_from(observed.len()).unwrap_or(i32::MAX);
        let overdue = self.sla.count_overdue(&allowed).await.map_err(PostureError::unexpected)?;
        let uncapped = named.as_ref().map(|weakest| weakest.score);
        Ok(Self::card(
            Some(scope.id),
            Some(kind.to_owned()),
            Some(scope.name.clone()),
            &Terms::of(&rows),
            licences,
            !observed.is_empty(),
            overdue,
            Coverage { total, observed: observed_count },
            uncapped,
            named,
        ))
    }

    /// Every target the caller may see that holds an open issue or a completed scan, graded by the computation its own
    /// card runs. A target holding neither is absent; a caller listing it anyway grades it [`TargetGrade::UNOBSERVED`].
    pub async fn grade_each(&self, allowed: &Visibility) -> Result<BTreeMap<ScanTarget, TargetGrade>, PostureError> {
        let violations = self.licences.violations(allowed).await.map_err(PostureError::unexpected)?;
        Ok(self.grade(allowed, &violations.by_target).await?.grades)
    }

    async fn grade(
        &self,
        allowed: &Visibility,
        violations: &BTreeMap<ScanTarget, i64>,
    ) -> Result<Graded, PostureError> {
        let rows = self
            .issues
            .count_for_grading_by_target(&open_within(allowed.clone()))
            .await
            .map_err(PostureError::unexpected)?;
        let terms_by_target = by_target(&rows);
        // Narrowed here, since the scans' targets are the estate's: a reader must not learn of a clean target they
        // were not given.
        let observed: BTreeSet<ScanTarget> = self
            .scans
            .targets_with_status(COMPLETED)
            .await
            .map_err(PostureError::unexpected)?
            .into_iter()
            .filter(|target| allowed.permits(*target))
            .collect();

        let graded: BTreeSet<ScanTarget> = terms_by_target.keys().copied().chain(observed.iter().copied()).collect();
        let mut grades = BTreeMap::new();
        for target in graded {
            let open = terms_by_target.get(&target).copied().unwrap_or_default();
            let scanned = observed.contains(&target);
            let refused = violations.get(&target).copied().unwrap_or_default();
            // The card's own computation, not a copy of its arithmetic.
            let score = CandidateScore::of(&open.weighed(refused), &WEIGHTS).score;
            let card =
                Self::card(None, None, None, &open, refused, scanned, 0, Coverage::of_one(scanned), Some(score), None);
            grades.insert(
                target,
                TargetGrade {
                    score: card.score,
                    grade: card.grade,
                    risk_points: card.risk_points,
                    critical: open.critical,
                    high: open.high,
                    medium: open.medium,
                    low: open.low,
                },
            );
        }
        Ok(Graded { grades, whole: Terms::of(&rows) })
    }

    /// For the simulation only: every visible target's open backlog in the formula's classes and its refused
    /// licences. A target with nothing open and nothing refused is absent.
    pub async fn candidate_counts(&self, allowed: &Visibility) -> Result<BTreeMap<ScanTarget, Counts>, PostureError> {
        let rows = self
            .issues
            .count_for_grading_by_target(&open_within(allowed.clone()))
            .await
            .map_err(PostureError::unexpected)?;
        let terms_by_target = by_target(&rows);
        let violations = self.licences.violations(allowed).await.map_err(PostureError::unexpected)?.by_target;
        let listed: BTreeSet<ScanTarget> = terms_by_target
            .keys()
            .copied()
            .chain(violations.iter().filter(|(_, refused)| **refused > 0).map(|(target, _)| *target))
            .collect();
        Ok(listed
            .into_iter()
            .map(|target| {
                let terms = terms_by_target.get(&target).copied().unwrap_or_default();
                (target, terms.weighed(violations.get(&target).copied().unwrap_or_default()))
            })
            .collect())
    }

    /// For the simulation only: each scope graded by the formula over its summed backlog — the aggregation decision
    /// 0036 rejected, kept so that the simulation still shows what the choice was between.
    pub async fn candidate_scopes(
        &self,
        scopes: &[VisibleScope],
        weights: &Weights,
    ) -> Result<Vec<ScopeCandidate>, PostureError> {
        let every: BTreeSet<ScanTarget> = scopes.iter().flat_map(|scope| scope.visible.iter().copied()).collect();
        let violations = self
            .licences
            .violations(&Visibility::Only(every.clone()))
            .await
            .map_err(PostureError::unexpected)?
            .by_target;
        let completed = self.completed_among(&every).await?;
        let mut graded = Vec::new();
        for scope in scopes {
            let licences: i64 =
                scope.visible.iter().map(|target| violations.get(target).copied().unwrap_or_default()).sum();
            let allowed = Visibility::Only(scope.visible.iter().copied().collect());
            let rows = self
                .issues
                .count_for_grading_by_target(&open_within(allowed))
                .await
                .map_err(PostureError::unexpected)?;
            let counts = Terms::of(&rows).weighed(licences);
            let total = i32::try_from(scope.visible.len()).unwrap_or(i32::MAX);
            let observed = i32::try_from(scope.visible.iter().filter(|target| completed.contains(target)).count())
                .unwrap_or(i32::MAX);
            if observed == 0 {
                graded.push(ScopeCandidate {
                    scope: scope.clone(),
                    counts,
                    total_targets: total,
                    observed_targets: 0,
                    score: None,
                    grade: SecurityGrade::NoData,
                    exact: None,
                    risk_points: None,
                });
                continue;
            }
            let result = CandidateScore::of(&counts, weights);
            let score = coverage::capped(result.score, total, observed);
            graded.push(ScopeCandidate {
                scope: scope.clone(),
                counts,
                total_targets: total,
                observed_targets: observed,
                score: Some(score),
                grade: SecurityGrade::from_score(score),
                exact: Some(CandidateScore::exact(&counts, weights)),
                risk_points: Some(result.risk_points),
            });
        }
        Ok(graded)
    }

    /// The weakest target, named as the caller sees it named everywhere else.
    async fn named(&self, target: ScanTarget, score: i32, risk_points: f64) -> Result<WeakestTarget, PostureError> {
        let (repository, container) = (repository_id(target), container_id(target));
        let names = naming::for_ids(&self.db, &repository.into_iter().collect(), &container.into_iter().collect())
            .await
            .map_err(PostureError::unexpected)?;
        Ok(WeakestTarget {
            target_kind: kind_of(container).to_owned(),
            target_id: id_of(target),
            target_name: names.of(repository, container),
            score,
            grade: SecurityGrade::from_score(score),
            risk_points,
        })
    }

    async fn completed_among(&self, among: &BTreeSet<ScanTarget>) -> Result<BTreeSet<ScanTarget>, PostureError> {
        Ok(self
            .scans
            .targets_with_status(COMPLETED)
            .await
            .map_err(PostureError::unexpected)?
            .into_iter()
            .filter(|target| among.contains(target))
            .collect())
    }

    /// A card: the score handed in, held at the coverage, with the risk points of `open` and the recommendations.
    #[allow(clippy::too_many_arguments)]
    fn card(
        target_id: Option<i64>,
        target_kind: Option<String>,
        target_name: Option<String>,
        open: &Terms,
        licence_violations: i64,
        has_attestation: bool,
        overdue: i64,
        coverage: Coverage,
        uncapped: Option<i32>,
        weakest: Option<WeakestTarget>,
    ) -> SecurityScorecard {
        let mut recommendations = Vec::new();
        if licence_violations > 0 {
            recommendations
                .push(format!("Remediate {licence_violations} disallowed open source license violation(s)."));
        }
        // The attestation is issued on demand from any completed scan: the only way to earn it is to complete one.
        if !has_attestation {
            recommendations
                .push("Complete a scan: no in-toto attestation can be issued for a target never scanned.".to_owned());
        }
        if open.kev > 0 {
            recommendations
                .push(format!("Urgent: Eliminate {} actively exploited CISA KEV vulnerability(ies).", open.kev));
        }
        if open.critical > 0 {
            recommendations.push(format!("Prioritize resolution of {} critical severity issue(s).", open.critical));
        }
        if open.high > 0 {
            recommendations.push(format!("Schedule remediation of {} high severity issue(s).", open.high));
        }
        // Advised on, not scored: a deadline is a deployment's setting, and the grade is what a public badge carries.
        if overdue > 0 {
            recommendations.push(format!("Resolve {overdue} issue(s) past their remediation deadline."));
        }
        let never = coverage.never();
        if coverage.observed > 0 && never > 0 {
            recommendations.insert(
                0,
                format!(
                    "Scan the {never} target(s) never scanned: the score covers {}/{} target(s), and is capped at that share.",
                    coverage.observed, coverage.total
                ),
            );
        }
        if recommendations.is_empty() {
            recommendations.push("Maintain current posture with continuous automated scanning.".to_owned());
        }

        // Nothing observed is no grade at all (decision 0007), not the hundred an empty backlog would give.
        let score = match uncapped {
            Some(uncapped) if coverage.observed > 0 => {
                Some(coverage::capped(uncapped, coverage.total, coverage.observed))
            }
            _ => None,
        };
        let grade = score.map_or(SecurityGrade::NoData, SecurityGrade::from_score);
        SecurityScorecard {
            target_id,
            target_kind,
            target_name,
            score,
            grade,
            risk_points: score.map(|_| CandidateScore::risk_points(&open.weighed(licence_violations), &WEIGHTS)),
            total_targets: coverage.total,
            observed_targets: coverage.observed,
            open_critical_count: open.critical,
            open_high_count: open.high,
            open_kev_count: open.kev,
            overdue_count: overdue,
            license_violation_count: licence_violations,
            has_attestation,
            weakest_target: if score.is_some() { weakest } else { None },
            recommendations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        repo: Option<i64>,
        container: Option<i64>,
        severity: Option<&str>,
        kev: bool,
        state: &str,
        c: i64,
    ) -> TargetGradingCount {
        TargetGradingCount {
            repo_id: repo,
            container_id: container,
            severity: severity.map(str::to_owned),
            is_kev: kev,
            state: state.to_owned(),
            c,
        }
    }

    #[test]
    fn the_backlog_is_shown_with_kev_under_its_severity_and_weighed_with_kev_alone() {
        let rows = [
            row(Some(1), None, Some("critical"), true, "open", 2),
            row(Some(1), None, Some("HIGH"), false, "Open", 3),
            row(Some(1), None, None, false, "open", 1),
            row(Some(1), None, Some("weird"), false, "open", 4),
            row(Some(1), None, Some("critical"), false, "closed", 5),
            row(Some(1), None, Some("high"), false, "RESOLVED", 6),
        ];
        let terms = Terms::of(&rows);
        assert_eq!((terms.critical, terms.high, terms.medium, terms.low, terms.kev), (2, 3, 1, 4, 2));
        assert_eq!(terms.weighed(7), Counts { exploited: 2, critical: 0, high: 3, medium: 1, low: 4, licences: 7 });
    }

    #[test]
    fn a_row_naming_both_targets_is_its_repository_s_and_one_naming_neither_ranks_nowhere() {
        let rows = [
            row(Some(1), Some(9), Some("high"), false, "open", 2),
            row(None, Some(9), Some("low"), false, "open", 1),
            row(None, None, Some("critical"), false, "open", 8),
            row(Some(2), None, Some("high"), false, "closed", 1),
        ];
        let by = by_target(&rows);
        assert_eq!(by.keys().copied().collect::<Vec<_>>(), vec![ScanTarget::Repository(1), ScanTarget::Container(9)]);
        assert_eq!(by[&ScanTarget::Repository(1)].high, 2);
        assert_eq!(by[&ScanTarget::Container(9)].low, 1);
    }

    #[test]
    fn nothing_observed_is_no_grade() {
        let card = SecurityScorecards::card(
            None,
            None,
            None,
            &Terms::default(),
            0,
            false,
            0,
            Coverage::of_one(false),
            Some(100),
            None,
        );
        assert_eq!((card.score, card.grade, card.risk_points), (None, SecurityGrade::NoData, None));
        assert_eq!(
            card.recommendations,
            vec!["Complete a scan: no in-toto attestation can be issued for a target never scanned.".to_owned()]
        );
    }

    #[test]
    fn a_partly_observed_scope_is_capped_at_its_share_and_says_so_first() {
        let weakest = WeakestTarget {
            target_kind: "repository".to_owned(),
            target_id: 4,
            target_name: "r".to_owned(),
            score: 100,
            grade: SecurityGrade::APlus,
            risk_points: 0.0,
        };
        let open = Terms { high: 1, weighed: [0, 1, 0, 0, 0], ..Terms::default() };
        let card = SecurityScorecards::card(
            Some(1),
            Some("project".to_owned()),
            Some("p".to_owned()),
            &open,
            2,
            true,
            3,
            Coverage { total: 3, observed: 2 },
            Some(100),
            Some(weakest.clone()),
        );
        assert_eq!((card.score, card.grade), (Some(67), SecurityGrade::C));
        assert_eq!(card.risk_points, Some(12.0));
        assert_eq!(card.weakest_target, Some(weakest));
        assert_eq!(
            card.recommendations,
            vec![
                "Scan the 1 target(s) never scanned: the score covers 2/3 target(s), and is capped at that share.",
                "Remediate 2 disallowed open source license violation(s).",
                "Schedule remediation of 1 high severity issue(s).",
                "Resolve 3 issue(s) past their remediation deadline.",
            ]
        );
    }

    #[test]
    fn a_card_advises_on_exploited_then_critical_then_high() {
        let open = Terms { critical: 2, high: 1, kev: 1, ..Terms::default() };
        let card =
            SecurityScorecards::card(None, None, None, &open, 0, true, 0, Coverage::of_one(true), Some(40), None);
        assert_eq!(
            card.recommendations,
            vec![
                "Urgent: Eliminate 1 actively exploited CISA KEV vulnerability(ies).",
                "Prioritize resolution of 2 critical severity issue(s).",
                "Schedule remediation of 1 high severity issue(s).",
            ]
        );
        let clean = SecurityScorecards::card(
            None,
            None,
            None,
            &Terms::default(),
            0,
            true,
            0,
            Coverage::of_one(true),
            Some(100),
            None,
        );
        assert_eq!(clean.recommendations, vec!["Maintain current posture with continuous automated scanning."]);
        assert_eq!((clean.score, clean.grade), (Some(100), SecurityGrade::APlus));
    }

    #[test]
    fn the_weaker_is_the_lower_score_then_the_more_risk() {
        let at = |score, risk_points| ScoreResult { score, grade: SecurityGrade::from_score(score), risk_points };
        assert!(weaker(&at(40, 1.0), &at(50, 9.0)));
        assert!(weaker(&at(1, 900.0), &at(1, 10.0)));
        assert!(!weaker(&at(1, 10.0), &at(1, 10.0)));
        assert!(!weaker(&at(60, 0.0), &at(50, 9.0)));
    }
}
