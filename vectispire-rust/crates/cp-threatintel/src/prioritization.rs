//! The fleet's exploitation ranking — Java's `EpssPrioritizationService` and the records of `EpssRiskMatrix` it
//! fills, shaped as `EpssFleetSummaryView` serializes them.
//!
//! **Within the caller's allowance.** The read was once every issue of the deployment with no visibility at all, so a
//! restricted reader received every other target's most exploitable vulnerabilities, ranked. **Settled triage is left
//! out**, as on the scorecard and the gate: a CVE argued `not_affected` must not head the list of what to fix first.
//! And **unknown stays unknown**: a CVE neither the scan nor the feed scored is reported with no score, and only the
//! risk matrix's own default sorts it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Serialize, Serializer};
use vectispire_cp_db::Visibility;
use vectispire_cp_issues::queries::{EpssRow, IssueCatalog, IssueFilters};
use vectispire_cp_targets::Targets;
use vectispire_cp_targets::naming::{of_container_view, of_repository_view};
use vectispire_domain::java;

use crate::feeds::{FeedError, ThreatIntel};
use crate::risk_matrix::{self, CRITICAL_ARMED, HIGH_PROBABLE, LOW_PROBABILITY, MEDIUM_THEORETICAL, RecommendedAction};

/// `RANKED`: how many ranked issues the summary carries. The counts still weigh every issue, and
/// `totalVulnerabilities` carries the true figure beside the cut.
pub const RANKED: usize = 50;

/// The EPSS score from which an issue counts as likely exploited.
const HIGH_EPSS: f64 = 0.20;

/// `EpssPrioritizedIssue`, members in the record's order.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrioritizedIssue {
    pub issue_id: i64,
    pub identifier: String,
    pub title: String,
    pub severity: Option<String>,
    pub cvss_score: Option<f64>,
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub is_kev: bool,
    pub target_name: String,
    pub target_kind: &'static str,
    pub priority_score: i32,
    pub priority_tier: &'static str,
    pub recommended_action: RecommendedAction,
}

/// The four tiers' counts, every tier present, in the order Java's `HashMap` of these four names iterates — what the
/// wire has always carried.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TierBreakdown {
    pub critical_armed: i32,
    pub high_probable: i32,
    pub medium_theoretical: i32,
    pub low_probability: i32,
}

impl TierBreakdown {
    fn count(&mut self, tier: &str) {
        let slot = match tier {
            CRITICAL_ARMED => &mut self.critical_armed,
            HIGH_PROBABLE => &mut self.high_probable,
            MEDIUM_THEORETICAL => &mut self.medium_theoretical,
            _ => &mut self.low_probability,
        };
        *slot = slot.saturating_add(1);
    }
}

impl Serialize for TierBreakdown {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map([
            (MEDIUM_THEORETICAL, self.medium_theoretical),
            (HIGH_PROBABLE, self.high_probable),
            (LOW_PROBABILITY, self.low_probability),
            (CRITICAL_ARMED, self.critical_armed),
        ])
    }
}

/// `EpssFleetSummary`, members in the record's order.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetSummary {
    pub total_vulnerabilities: i32,
    pub active_kev_count: i32,
    pub high_epss_count: i32,
    pub average_fleet_epss: f64,
    pub top_priorities: Vec<PrioritizedIssue>,
    pub breakdown_by_tier: TierBreakdown,
}

/// The ranking over the backlog, the targets' names and the two feeds.
#[derive(Clone)]
pub struct EpssPrioritizationService {
    issues: Arc<IssueCatalog>,
    targets: Arc<Targets>,
    feeds: ThreatIntel,
}

impl std::fmt::Debug for EpssPrioritizationService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("EpssPrioritizationService").finish_non_exhaustive()
    }
}

impl EpssPrioritizationService {
    pub fn new(issues: Arc<IssueCatalog>, targets: Arc<Targets>, feeds: ThreatIntel) -> EpssPrioritizationService {
        EpssPrioritizationService { issues, targets, feeds }
    }

    /// `getFleetSummary`.
    pub async fn fleet_summary(&self, allowed: &Visibility) -> Result<FleetSummary, FeedError> {
        // `new IssueFilters(null, …, excludeSettled = true, …, allowed)`: every state, then the closed and resolved
        // ones left out as Java does, by name and ignoring case.
        let filters = IssueFilters { state: None, exclude_settled: true, ..IssueFilters::new(allowed.clone()) };
        let open: Vec<EpssRow> = self
            .issues
            .epss_rows(&filters)
            .await
            .map_err(unexpected)?
            .into_iter()
            .filter(|row| !row.state.eq_ignore_ascii_case("closed") && !row.state.eq_ignore_ascii_case("resolved"))
            .collect();

        // Named by the targets these issues belong to, not by reading the whole estate to look two of them up.
        let repository_ids: BTreeSet<i64> = open.iter().filter_map(|row| row.repo_id).collect();
        let container_ids: BTreeSet<i64> = open.iter().filter_map(|row| row.container_id).collect();
        let repositories: BTreeMap<i64, String> = self
            .targets
            .catalog_repositories_by_ids(&repository_ids)
            .await
            .map_err(unexpected)?
            .iter()
            .map(|view| (view.id, of_repository_view(view)))
            .collect();
        let containers: BTreeMap<i64, String> = self
            .targets
            .catalog_containers_by_ids(&container_ids)
            .await
            .map_err(unexpected)?
            .iter()
            .map(|view| (view.id, of_container_view(view)))
            .collect();

        // One query per feed for the whole backlog, not one per issue.
        let intel = self.feeds.lookup_cves(open.iter().filter_map(|row| row.identifier.as_deref())).await?;

        let mut ranked = Vec::with_capacity(open.len());
        let mut breakdown = TierBreakdown::default();
        let (mut active_kev, mut high_epss, mut scored) = (0_i32, 0_i32, 0_i32);
        let mut total_epss = 0.0_f64;
        for issue in &open {
            let record = issue.identifier.as_deref().and_then(|cve| intel.get(&java::to_lower_root(java::trim(cve))));
            let is_kev = issue.is_kev || record.is_some_and(|record| record.is_kev);
            let epss_score = issue.epss_score.or_else(|| record.and_then(|record| record.epss_score));
            let epss_percentile = record.and_then(|record| record.epss_percentile);
            if is_kev {
                active_kev = active_kev.saturating_add(1);
            }
            if let Some(score) = epss_score {
                if score >= HIGH_EPSS {
                    high_epss = high_epss.saturating_add(1);
                }
                total_epss += score;
                scored = scored.saturating_add(1);
            }
            let cvss = issue.cvss_score;
            let tier = risk_matrix::tier(cvss, epss_score, is_kev);
            breakdown.count(tier);
            ranked.push(PrioritizedIssue {
                issue_id: issue.id,
                identifier: issue.identifier.clone().unwrap_or_else(|| issue.type_.clone()),
                title: issue
                    .description
                    .clone()
                    .or_else(|| issue.package_name.clone())
                    .unwrap_or_else(|| format!("Vulnerability {}", issue.id)),
                severity: issue.severity.clone(),
                cvss_score: cvss,
                epss_score,
                epss_percentile,
                is_kev,
                target_name: target_name(issue, &repositories, &containers),
                target_kind: if issue.repo_id.is_some() { "REPOSITORY" } else { "CONTAINER" },
                priority_score: risk_matrix::priority_score(cvss, epss_score, is_kev),
                priority_tier: tier,
                recommended_action: risk_matrix::action(tier, is_kev),
            });
        }
        // Stable, as `List.sort` is: ties keep the backlog's order. Ranked over everything, then cut — cutting first
        // would return fifty arbitrary issues and call them the worst.
        ranked.sort_by_key(|issue| std::cmp::Reverse(issue.priority_score));
        ranked.truncate(RANKED);

        let average = if scored > 0 { total_epss / f64::from(scored) } else { 0.0 };
        Ok(FleetSummary {
            total_vulnerabilities: i32::try_from(open.len()).unwrap_or(i32::MAX),
            active_kev_count: active_kev,
            high_epss_count: high_epss,
            average_fleet_epss: thousandths(average),
            top_priorities: ranked,
            breakdown_by_tier: breakdown,
        })
    }
}

/// `Math.round(average * 1000.0) / 1000.0`.
fn thousandths(average: f64) -> f64 {
    let rounded = vectispire_domain::java_math::round(average * 1000.0);
    // Sound: a mean of probabilities times a thousand is far inside the range a double holds exactly as an integer.
    #[allow(clippy::cast_precision_loss)]
    let rounded = rounded as f64;
    rounded / 1000.0
}

/// `TargetNaming`'s name of the issue's target, by its repository first; `target-<id>` for one the catalogue no longer
/// has — and, as Java's concatenation writes it, `target-null` for an issue that names neither.
fn target_name(issue: &EpssRow, repositories: &BTreeMap<i64, String>, containers: &BTreeMap<i64, String>) -> String {
    if let Some(name) = issue.repo_id.and_then(|id| repositories.get(&id)) {
        return name.clone();
    }
    if let Some(name) = issue.container_id.and_then(|id| containers.get(&id)) {
        return name.clone();
    }
    match issue.repo_id.or(issue.container_id) {
        Some(id) => format!("target-{id}"),
        None => "target-null".to_owned(),
    }
}

fn unexpected(error: impl std::error::Error + Send + Sync + 'static) -> FeedError {
    FeedError(Box::new(error))
}
