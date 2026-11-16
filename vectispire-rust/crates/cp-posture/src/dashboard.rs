//! `DashboardQueryService` and `PostureScoreboards`: the home page's figures, read once and narrowed by the caller's
//! visibility. **It computes no aggregate of its own**: the posture is the gate's overview — the one the security
//! screen shows — and the backlog the issues' own criteria; a home page that reimplemented its figures would show
//! different ones from the screens behind it, and it is the one people believe.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::Serialize;
use time::{Date, Duration, OffsetDateTime};
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_gate::{GateService, TargetPosture, ViolationView};
use vectispire_cp_issues::queries::TargetResolutions;
use vectispire_cp_issues::{IssueCatalog, IssueFilters, SlaService};
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_scanning::views::ScanView;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::Clock;
use vectispire_cp_targets::naming::{self, Names};
use vectispire_domain::java;

use crate::error::PostureError;
use crate::remediation::SEVERITIES;
use crate::scorecards::{SecurityScorecards, TargetGrade, container_id, id_of, kind_of, repository_id, target_of};
use crate::trends::{
    BacklogTrend, IssueObservation, Lifespan, PostureTrendAnalytics, TargetMaturityScore, day_of, iso,
};

const RECENT_SCANS: usize = 8;

/// The longest series drawn: the window is also the number of days iterated over every issue in scope.
const MAX_TREND_DAYS: i32 = 365;

/// The internal row migration V69 writes at the upgrade to 0.11.0, where there were grades.
const SCORE_FORMULA_CHANGED_ON: &str = "internal.scorecard_formula_changed_on";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Posture {
    pub failing_count: i32,
    pub total_count: i32,
    pub kev_count: i64,
    pub never_scanned_count: i64,
    pub last_scan_failed_count: i64,
    /// Open issues past their remediation window — zero when every window is disabled.
    pub overdue_count: i64,
}

/// A failing target, its violations as the wire spells them (`rule` lowercase, which the screen compares).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailingTarget {
    pub kind: &'static str,
    pub target_id: i64,
    pub name: String,
    pub observed: bool,
    pub violations: Vec<ViolationView>,
}

/// A recent scan, named as the operator recognises it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentScan {
    pub id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub target_kind: &'static str,
    pub target_name: String,
    pub status: String,
    pub findings_count: i32,
    pub error: Option<String>,
    #[serde(serialize_with = "instant")]
    pub created_at: OffsetDateTime,
}

fn instant<S: serde::Serializer>(at: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&vectispire_cp_audit::iso_instant(*at))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardOverview {
    pub posture: Posture,
    /// Most severe first; a severity nobody has is absent rather than zero.
    pub backlog_by_severity: serde_json::Map<String, serde_json::Value>,
    /// Apart, and never mixed into the security backlog: it blocks nothing.
    pub quality_total: i64,
    pub failing: Vec<FailingTarget>,
    pub recent_scans: Vec<RecentScan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrendPoint {
    /// An ISO date, UTC — the axis means the same thing in two timezones.
    pub day: String,
    pub open: i64,
    pub opened: i64,
    pub resolved: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Trends {
    pub points: Vec<TrendPoint>,
    pub mean_days_to_resolve: Option<f64>,
    pub resolved_in_window: i32,
    pub score_formula_changed_on: Option<String>,
}

#[derive(Clone)]
pub struct Dashboard {
    db: Db,
    gate: Arc<GateService>,
    issues: Arc<IssueCatalog>,
    sla: Arc<SlaService>,
    scans: Arc<ScanCatalog>,
    scorecards: Arc<SecurityScorecards>,
    settings: Arc<Settings>,
    clock: Arc<dyn Clock>,
}

opaque_debug!(Dashboard);

/// Every issue the reader may see, whatever its state.
pub(crate) fn every_issue(allowed: Visibility) -> IssueFilters {
    IssueFilters { state: None, ..IssueFilters::new(allowed) }
}

/// The open, unsettled backlog per severity, **within what the caller may see**, most severe first — one count per
/// severity through the backlog's own criteria, so each figure and the list it links to agree.
pub(crate) async fn backlog_by_severity(
    issues: &IssueCatalog,
    allowed: &Visibility,
) -> Result<Vec<(String, i64)>, PostureError> {
    let mut counts = Vec::new();
    for severity in SEVERITIES {
        let filters = IssueFilters {
            state: Some("open".to_owned()),
            severity: Some(severity.wire_name().to_owned()),
            exclude_settled: true,
            ..IssueFilters::new(allowed.clone())
        };
        let count = issues.count(&filters).await.map_err(PostureError::unexpected)?;
        if count > 0 {
            counts.push((severity.wire_name().to_owned(), count));
        }
    }
    Ok(counts)
}

impl Dashboard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        gate: Arc<GateService>,
        issues: Arc<IssueCatalog>,
        sla: Arc<SlaService>,
        scans: Arc<ScanCatalog>,
        scorecards: Arc<SecurityScorecards>,
        settings: Arc<Settings>,
        clock: Arc<dyn Clock>,
    ) -> Dashboard {
        Dashboard { db, gate, issues, sla, scans, scorecards, settings, clock }
    }

    pub async fn overview(&self, allowed: &Visibility) -> Result<DashboardOverview, PostureError> {
        let posture = self.gate.overview(allowed).await.map_err(PostureError::unexpected)?;
        let overdue = self.sla.count_overdue(allowed).await.map_err(PostureError::unexpected)?;
        let mut backlog = serde_json::Map::new();
        for (severity, count) in backlog_by_severity(&self.issues, allowed).await? {
            backlog.insert(severity, serde_json::Value::from(count));
        }
        // Within the allowance, like every other figure here.
        let quality = IssueFilters {
            state: Some("open".to_owned()),
            type_: Some("quality".to_owned()),
            ..IssueFilters::new(allowed.clone())
        };
        let quality_total = self.issues.count(&quality).await.map_err(PostureError::unexpected)?;
        Ok(DashboardOverview {
            posture: Posture {
                failing_count: posture.failing_count,
                total_count: posture.total_count,
                kev_count: posture.kev_count,
                never_scanned_count: posture.never_scanned_count,
                last_scan_failed_count: posture.last_scan_failed_count,
                overdue_count: overdue,
            },
            backlog_by_severity: backlog,
            quality_total,
            failing: posture.targets.iter().filter(|target| !target.passed).map(failing_of).collect(),
            recent_scans: self.recent_scans(allowed).await?,
        })
    }

    /// The last scans the caller may see, named.
    async fn recent_scans(&self, allowed: &Visibility) -> Result<Vec<RecentScan>, PostureError> {
        let recent = self.scans.recent(allowed, RECENT_SCANS).await.map_err(PostureError::unexpected)?;
        let repositories: BTreeSet<i64> = recent.iter().filter_map(|scan| scan.repo_id).collect();
        let containers: BTreeSet<i64> = recent.iter().filter_map(|scan| scan.container_id).collect();
        let names = naming::for_ids(&self.db, &repositories, &containers).await.map_err(PostureError::unexpected)?;
        Ok(recent.iter().map(|scan| recent_of(scan, &names)).collect())
    }

    /// The day, UTC, this installation's grades changed formula, or none. A row that does not read as a date — edited
    /// by hand — draws no line rather than one on a wrong day.
    async fn score_formula_changed_on(&self) -> Result<Option<String>, PostureError> {
        let value = self.settings.internal_value(SCORE_FORMULA_CHANGED_ON).await.map_err(PostureError::unexpected)?;
        Ok(value.map(|value| java::trim(&value).to_owned()).filter(|value| parse_iso_date(value).is_some()))
    }

    /// The backlog over time: every issue, not only the open ones — an issue resolved in the window is open on the
    /// days before — two columns each.
    pub async fn trends(&self, days: i32, allowed: &Visibility) -> Result<Trends, PostureError> {
        // Clamped rather than refused: a chart is no place to fail a request over a query string.
        let window = days.clamp(1, MAX_TREND_DAYS);
        let to = day_of(self.clock.now());
        let from = to.checked_sub(Duration::days(i64::from(window.saturating_sub(1)))).unwrap_or(to);
        let lifespans: Vec<Lifespan> = self
            .issues
            .observations(&every_issue(allowed.clone()))
            .await
            .map_err(PostureError::unexpected)?
            .into_iter()
            .map(|row| Lifespan { first_seen: Some(row.first_seen_at), resolved_at: row.resolved_at })
            .collect();
        let series = BacklogTrend::over(&lifespans, from, to);
        Ok(Trends {
            points: series
                .points
                .iter()
                .map(|point| TrendPoint {
                    day: iso(point.day),
                    open: point.open,
                    opened: point.opened,
                    resolved: point.resolved,
                })
                .collect(),
            mean_days_to_resolve: series.mean_days_to_resolve,
            resolved_in_window: series.resolved_in_window,
            score_formula_changed_on: self.score_formula_changed_on().await?,
        })
    }

    /// Two reads of two shapes: the curve from the issues that touch the window, the scoreboard over all time.
    pub async fn posture_analytics(
        &self,
        days: i32,
        allowed: &Visibility,
    ) -> Result<PostureTrendAnalytics, PostureError> {
        let window = days.clamp(7, MAX_TREND_DAYS);
        let now = self.clock.now();
        let window_start = PostureTrendAnalytics::window_start(window, now);
        let visible = every_issue(allowed.clone());
        let touching = self
            .issues
            .observations(&visible.clone().touching(window_start))
            .await
            .map_err(PostureError::unexpected)?;

        // The ranking is the scorecards', graded by their service; what each target closed and how fast is this page's.
        let grades = self.scorecards.grade_each(allowed).await?;
        let resolved = self.issues.count_resolved_by_target(&visible).await.map_err(PostureError::unexpected)?;
        let ranked = Scoreboards::listed(&grades, &resolved);

        // Named once for both halves.
        let repositories: BTreeSet<i64> = touching
            .iter()
            .filter_map(|row| row.repo_id)
            .chain(ranked.iter().filter_map(|target| repository_id(*target)))
            .collect();
        let containers: BTreeSet<i64> = touching
            .iter()
            .filter_map(|row| row.container_id)
            .chain(ranked.iter().filter_map(|target| container_id(*target)))
            .collect();
        let names = naming::for_ids(&self.db, &repositories, &containers).await.map_err(PostureError::unexpected)?;

        let observations: Vec<IssueObservation> = touching
            .iter()
            .map(|row| IssueObservation {
                target_id: row.repo_id.or(row.container_id),
                target_kind: if row.repo_id.is_some() { "REPOSITORY" } else { "CONTAINER" }.to_owned(),
                target_name: names.of(row.repo_id, row.container_id),
                severity: row.severity.clone().unwrap_or_else(|| "MEDIUM".to_owned()),
                first_seen: Some(row.first_seen_at),
                resolved_at: row.resolved_at,
            })
            .collect();
        Ok(PostureTrendAnalytics::calculate(window, now, &observations, Scoreboards::from(&grades, &resolved, &names)))
    }
}

fn failing_of(posture: &TargetPosture) -> FailingTarget {
    FailingTarget {
        kind: match posture.target {
            ScanTarget::Repository(_) => "repository",
            ScanTarget::Container(_) => "container",
        },
        target_id: id_of(posture.target),
        name: posture.name.clone(),
        observed: posture.observed,
        violations: ViolationView::list_of(&posture.verdict.violations),
    }
}

/// The target, with the scan's branch — the scan's, not the repository's, which may have changed since. Images are
/// left alone: their scans carry `n/a` there.
fn recent_of(scan: &ScanView, names: &Names) -> RecentScan {
    let name = names.of(scan.repo_id, scan.container_id);
    let target_name = if scan.container_id.is_some() || java::is_blank(&scan.branch) {
        name
    } else {
        format!("{name} — {}", scan.branch)
    };
    RecentScan {
        id: scan.id,
        repo_id: scan.repo_id,
        container_id: scan.container_id,
        target_kind: kind_of(scan.container_id),
        target_name,
        status: scan.status.clone(),
        findings_count: scan.findings_count,
        error: scan.error.clone(),
        created_at: scan.created_at,
    }
}

/// `LocalDate.parse`: `yyyy-MM-dd`, a real day.
fn parse_iso_date(value: &str) -> Option<Date> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = value.get(range)?;
        if part.bytes().all(|b| b.is_ascii_digit()) { part.parse().ok() } else { None }
    };
    let year = i32::try_from(digits(0..4)?).ok()?;
    let month = time::Month::try_from(u8::try_from(digits(5..7)?).ok()?).ok()?;
    let day = u8::try_from(digits(8..10)?).ok()?;
    Date::from_calendar_date(year, month, day).ok()
}

/// `PostureScoreboards`: the all-time half of the posture page, the maturity ranking. **It grades nothing** — each
/// row's score and grade are its scorecard's.
#[derive(Debug, Clone, Copy)]
pub struct Scoreboards;

impl Scoreboards {
    /// Every target the ranking lists, repositories then images, each by id — the order ties keep.
    pub fn listed(grades: &BTreeMap<ScanTarget, TargetGrade>, resolved: &[TargetResolutions]) -> Vec<ScanTarget> {
        let listed: BTreeSet<ScanTarget> = grades
            .keys()
            .copied()
            .chain(resolved.iter().filter_map(|row| target_of(row.repo_id, row.container_id)))
            .collect();
        listed.into_iter().collect()
    }

    /// Graded first, best score first, then the fewer risk points; the ungraded after them, in listing order.
    pub fn from(
        grades: &BTreeMap<ScanTarget, TargetGrade>,
        resolved: &[TargetResolutions],
        names: &Names,
    ) -> Vec<TargetMaturityScore> {
        let mut closed: BTreeMap<ScanTarget, &TargetResolutions> = BTreeMap::new();
        for row in resolved {
            if let Some(target) = target_of(row.repo_id, row.container_id) {
                closed.insert(target, row);
            }
        }
        let mut ranking: Vec<TargetMaturityScore> = Self::listed(grades, resolved)
            .into_iter()
            .map(|target| {
                let grade = grades.get(&target).copied().unwrap_or(TargetGrade::UNOBSERVED);
                let closed = closed.get(&target);
                let (repository, container) = (repository_id(target), container_id(target));
                TargetMaturityScore {
                    target_id: Some(id_of(target)),
                    target_kind: if repository.is_some() { "REPOSITORY" } else { "CONTAINER" }.to_owned(),
                    target_name: names.of(repository, container),
                    open_critical: grade.critical,
                    open_high: grade.high,
                    open_medium: grade.medium,
                    open_low: grade.low,
                    total_resolved: closed.map_or(0, |row| row.resolved),
                    // Seconds to days in the engine's own rounding, as the window's MTTR reads.
                    target_mttr_days: closed
                        .and_then(|row| row.average_seconds)
                        .map(|seconds| PostureTrendAnalytics::round_days(seconds / 86_400.0)),
                    security_score: grade.score,
                    maturity_grade: grade.grade,
                    risk_points: grade.risk_points,
                }
            })
            .collect();
        ranking.sort_by(|a, b| {
            let by_score = match (a.security_score, b.security_score) {
                (Some(x), Some(y)) => y.cmp(&x),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            };
            by_score.then_with(|| match (a.risk_points, b.risk_points) {
                (Some(x), Some(y)) => x.total_cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
        });
        ranking
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hand_edited_date_draws_no_line() {
        assert!(parse_iso_date("2026-02-29").is_none());
        assert!(parse_iso_date("2024-02-29").is_some());
        assert!(parse_iso_date("2026-1-01").is_none());
        assert!(parse_iso_date("yesterday").is_none());
    }
}

#[cfg(test)]
mod ranking {
    use super::*;
    use crate::scorecard::SecurityGrade;

    fn graded(score: Option<i32>, risk: Option<f64>) -> TargetGrade {
        TargetGrade {
            score,
            grade: score.map_or(SecurityGrade::NoData, SecurityGrade::from_score),
            risk_points: risk,
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
        }
    }

    #[test]
    fn graded_first_best_first_then_fewer_points_and_the_ungraded_last() {
        let grades = BTreeMap::from([
            (ScanTarget::Repository(1), graded(Some(1), Some(900.0))),
            (ScanTarget::Repository(2), graded(Some(1), Some(10.0))),
            (ScanTarget::Container(3), graded(Some(97), Some(1.0))),
            (ScanTarget::Repository(4), graded(None, None)),
        ]);
        let resolved = vec![TargetResolutions {
            repo_id: None,
            container_id: Some(5),
            resolved: 3,
            average_seconds: Some(129_600.0),
        }];
        let names = Names::default();
        let ranking = Scoreboards::from(&grades, &resolved, &names);
        let ids: Vec<(String, Option<i64>)> =
            ranking.iter().map(|row| (row.target_kind.clone(), row.target_id)).collect();
        assert_eq!(
            ids,
            vec![
                ("CONTAINER".to_owned(), Some(3)),
                ("REPOSITORY".to_owned(), Some(2)),
                ("REPOSITORY".to_owned(), Some(1)),
                ("REPOSITORY".to_owned(), Some(4)),
                ("CONTAINER".to_owned(), Some(5)),
            ]
        );
        let closed = ranking.last().unwrap();
        assert_eq!((closed.total_resolved, closed.target_mttr_days), (3, Some(1.5)));
        assert_eq!(closed.maturity_grade, SecurityGrade::NoData);
        assert_eq!((ranking[0].open_critical, ranking[0].open_low), (1, 4));
    }

    fn scan(repo: Option<i64>, container: Option<i64>, branch: &str) -> ScanView {
        ScanView {
            id: 1,
            branch: branch.to_owned(),
            sub_path: None,
            status: "completed".to_owned(),
            duration_ms: None,
            findings_count: 0,
            new_issues_count: 0,
            resolved_issues_count: 0,
            error: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            version: None,
            project_type: None,
            repo_id: repo,
            container_id: container,
            required_agent_label: None,
            claimed_by: None,
            claimed_at: None,
            lease_expires_at: None,
            attempts: 0,
            not_before: None,
            plugin_steps: None,
            examined_types: None,
            detected_languages: None,
            sast_languages: None,
            has_sbom: false,
        }
    }

    #[test]
    fn a_recent_scan_carries_its_own_branch_and_an_image_none() {
        let names = Names {
            repositories: BTreeMap::from([(1, "api".to_owned())]),
            containers: BTreeMap::from([(9, "alpine:3.20".to_owned())]),
        };
        assert_eq!(recent_of(&scan(Some(1), None, "main"), &names).target_name, "api — main");
        assert_eq!(recent_of(&scan(Some(1), None, " \u{1f} "), &names).target_name, "api");
        assert_eq!(recent_of(&scan(None, Some(9), "n/a"), &names).target_name, "alpine:3.20");
        assert_eq!(recent_of(&scan(Some(1), Some(9), "main"), &names).target_name, "api");
        assert_eq!(recent_of(&scan(None, Some(9), "n/a"), &names).target_kind, "container");
    }
}
