//! `SecurityDebtService`: what the open backlog would cost to clear, in hours per finding family, and the upgrades that
//! close the most of it — the remediation plan's three routes (`debt`, `high-impact-fixes`, `coverage`).
//!
//! The figures are narrowed by the caller's visibility through the backlog's criteria: a repository or image named on
//! the route that the caller may not see contributes nothing, as in Java — it is not refused.

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_db::Visibility;
use vectispire_cp_issues::queries::{PackageWeight, SeverityTypeCount};
use vectispire_cp_issues::{IssueCatalog, IssueFilters};
use vectispire_cp_targets::{Targets, naming};
use vectispire_domain::finding_type::GateParticipation;
use vectispire_domain::{FindingType, Severity, java};

use crate::arithmetic::tenths;
use crate::error::PostureError;
use crate::remediation::{HighImpactFix, OpenFamily, RemediationCoverage, SecurityDebtReport};
use crate::versions;

const SECRET_HOURS: f64 = 2.0;
const SOURCE_CODE_HOURS: f64 = 2.5;
const IAC_HOURS: f64 = 1.0;
const LICENSE_HOURS: f64 = 3.0;
const END_OF_LIFE_HOURS: f64 = 4.0;
const SEVERE_VULNERABILITY_HOURS: f64 = 1.5;
const ORDINARY_VULNERABILITY_HOURS: f64 = 0.8;

/// The report's own list: a short work order is the point.
const MOST_LEVERAGE: usize = 10;
/// The most a caller may ask for.
const MOST_LEVERAGE_EVER: i32 = 50;

#[derive(Debug, Default)]
struct Tallies {
    total: i64,
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    vulnerability_hours: f64,
    secret_hours: f64,
    source_code_hours: f64,
    iac_hours: f64,
    license_hours: f64,
    eol_hours: f64,
}

/// What one package's fixes close, gathered from its findings.
#[derive(Debug, Default)]
struct Detail {
    cves: Vec<String>,
    target_names: Vec<String>,
    fix_versions: Vec<String>,
}

/// `LinkedHashSet.add`.
fn add(set: &mut Vec<String>, value: String) {
    if !set.contains(&value) {
        set.push(value);
    }
}

fn effort_of(weight: &PackageWeight) -> f64 {
    tenths(1.0 + weight.distinct_identifiers as f64 * 0.1)
}

fn leverage_of(weight: &PackageWeight) -> f64 {
    tenths(
        (weight.distinct_identifiers as f64 * 2.0
            + weight.critical_count as f64 * 3.0
            + weight.high_count as f64 * 1.5)
            / effort_of(weight),
    )
}

#[derive(Clone)]
pub struct SecurityDebt {
    issues: Arc<IssueCatalog>,
    targets: Arc<Targets>,
}

opaque_debug!(SecurityDebt);

impl SecurityDebt {
    pub fn new(issues: Arc<IssueCatalog>, targets: Arc<Targets>) -> SecurityDebt {
        SecurityDebt { issues, targets }
    }

    fn open_issues_of(repository: Option<i64>, container: Option<i64>, allowed: &Visibility) -> IssueFilters {
        IssueFilters {
            state: Some("open".to_owned()),
            repo_id: repository,
            container_id: container,
            exclude_settled: true,
            ..IssueFilters::new(allowed.clone())
        }
    }

    pub async fn calculate_debt(
        &self,
        repository: Option<i64>,
        container: Option<i64>,
        allowed: &Visibility,
    ) -> Result<SecurityDebtReport, PostureError> {
        let filters = Self::open_issues_of(repository, container, allowed);
        let rows = self.issues.count_grouped_by_severity_and_type(&filters).await.map_err(PostureError::unexpected)?;
        let tallies = Self::tally(&rows);
        let total_hours = tenths(
            tallies.vulnerability_hours
                + tallies.secret_hours
                + tallies.source_code_hours
                + tallies.iac_hours
                + tallies.license_hours
                + tallies.eol_hours,
        );
        Ok(SecurityDebtReport {
            total_open_issues: tallies.total,
            critical_issues: tallies.critical,
            high_issues: tallies.high,
            medium_issues: tallies.medium,
            low_issues: tallies.low,
            total_estimated_hours: total_hours,
            // From the rounded total, the figure shown beside it.
            total_estimated_person_days: tenths(total_hours / 8.0),
            vulnerabilities_debt_hours: tenths(tallies.vulnerability_hours),
            secrets_debt_hours: tenths(tallies.secret_hours),
            sast_debt_hours: tenths(tallies.source_code_hours),
            iac_debt_hours: tenths(tallies.iac_hours),
            license_debt_hours: tenths(tallies.license_hours),
            eol_debt_hours: tenths(tallies.eol_hours),
            top_high_impact_fixes: self.rank(&filters, MOST_LEVERAGE).await?,
        })
    }

    /// Clamped into its bounds rather than refused: a plan is no place to answer 400.
    pub async fn high_impact_fixes(
        &self,
        repository: Option<i64>,
        container: Option<i64>,
        wanted: i32,
        allowed: &Visibility,
    ) -> Result<Vec<HighImpactFix>, PostureError> {
        let bounded = usize::try_from(wanted.clamp(1, MOST_LEVERAGE_EVER)).unwrap_or(MOST_LEVERAGE);
        self.rank(&Self::open_issues_of(repository, container, allowed), bounded).await
    }

    pub async fn coverage(
        &self,
        repository: Option<i64>,
        container: Option<i64>,
        allowed: &Visibility,
    ) -> Result<RemediationCoverage, PostureError> {
        let rows = self
            .issues
            .count_open_by_type_and_packaging(&Self::open_issues_of(repository, container, allowed))
            .await
            .map_err(PostureError::unexpected)?;
        let families: Vec<OpenFamily> = rows
            .into_iter()
            .map(|row| OpenFamily { type_: row.type_, package_named: row.package_named, unnamed: row.unnamed })
            .collect();
        Ok(RemediationCoverage::of(&families))
    }

    fn tally(rows: &[SeverityTypeCount]) -> Tallies {
        let mut tallies = Tallies::default();
        for row in rows {
            let severity = Severity::of(row.severity.as_deref());
            // An unrecognised type counts as a vulnerability: a finding in the count and in no estimate is the
            // alternative.
            let kind = FindingType::from_wire_name(Some(&row.type_)).unwrap_or(FindingType::Vulnerability);
            if kind.gate_participation() == GateParticipation::OnRequest {
                continue;
            }
            let count = row.c;
            tallies.total = tallies.total.saturating_add(count);
            match severity {
                Severity::Critical => tallies.critical = tallies.critical.saturating_add(count),
                Severity::High => tallies.high = tallies.high.saturating_add(count),
                Severity::Medium => tallies.medium = tallies.medium.saturating_add(count),
                Severity::Low | Severity::Negligible | Severity::Unknown => {
                    tallies.low = tallies.low.saturating_add(count)
                }
            }
            let hours = count as f64;
            match kind {
                FindingType::Vulnerability => {
                    tallies.vulnerability_hours += hours
                        * if matches!(severity, Severity::Critical | Severity::High) {
                            SEVERE_VULNERABILITY_HOURS
                        } else {
                            ORDINARY_VULNERABILITY_HOURS
                        };
                }
                FindingType::Secret => tallies.secret_hours += hours * SECRET_HOURS,
                FindingType::Sast | FindingType::Quality => tallies.source_code_hours += hours * SOURCE_CODE_HOURS,
                FindingType::Iac => tallies.iac_hours += hours * IAC_HOURS,
                FindingType::License => tallies.license_hours += hours * LICENSE_HOURS,
                FindingType::Eol => tallies.eol_hours += hours * END_OF_LIFE_HOURS,
                // Left out above, and named rather than left to a wildcard: a new type asks what it costs.
                FindingType::AiReview | FindingType::Plugin | FindingType::Imported => {}
            }
        }
        tallies
    }

    async fn rank(&self, filters: &IssueFilters, wanted: usize) -> Result<Vec<HighImpactFix>, PostureError> {
        let mut weights: Vec<PackageWeight> = self
            .issues
            .weigh_packages(filters)
            .await
            .map_err(PostureError::unexpected)?
            .into_iter()
            .filter(|weight| weight.distinct_identifiers > 0)
            .collect();
        // The most leverage first; ties by name so two runs on the same data agree.
        weights.sort_by(|a, b| {
            leverage_of(b)
                .total_cmp(&leverage_of(a))
                .then_with(|| java::compare_utf16(&a.package_name, &b.package_name))
        });
        weights.truncate(wanted);
        if weights.is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<String> = weights.iter().map(|weight| weight.package_name.clone()).collect();
        let details = self.details_of(filters, &names).await?;
        Ok(weights
            .into_iter()
            .map(|weight| {
                let detail = details.iter().find(|(name, _)| *name == weight.package_name).map(|(_, detail)| detail);
                HighImpactFix {
                    package_name: weight.package_name.clone(),
                    current_version: weight.version.clone().unwrap_or_else(|| "various".to_owned()),
                    // The version that fixes it, or nothing: "no fix published" is an answer of its own.
                    recommended_version: detail
                        .and_then(|detail| versions::highest(detail.fix_versions.iter().map(String::as_str))),
                    cve_count_resolved: weight.distinct_identifiers,
                    critical_cve_count: weight.critical_count,
                    high_cve_count: weight.high_count,
                    estimated_hours: effort_of(&weight),
                    leverage_score: leverage_of(&weight),
                    affected_cves: detail.map(|detail| detail.cves.clone()).unwrap_or_default(),
                    affected_target_names: detail.map(|detail| detail.target_names.clone()).unwrap_or_default(),
                }
            })
            .collect())
    }

    async fn details_of(
        &self,
        filters: &IssueFilters,
        packages: &[String],
    ) -> Result<Vec<(String, Detail)>, PostureError> {
        let rows = self.issues.detail_packages(filters, packages).await.map_err(PostureError::unexpected)?;
        let mut repositories = BTreeSet::new();
        let mut containers = BTreeSet::new();
        for row in &rows {
            if let Some(id) = row.repo_id {
                repositories.insert(id);
            } else if let Some(id) = row.container_id {
                containers.insert(id);
            }
        }
        // Through the targets' own naming: a repository with no name is called by its URL, as on every screen.
        let repository_names: Vec<(i64, String)> = self
            .targets
            .catalog_repositories_by_ids(&repositories)
            .await
            .map_err(PostureError::unexpected)?
            .iter()
            .map(|view| (view.id, naming::of_repository_view(view)))
            .collect();
        let container_names: Vec<(i64, String)> = self
            .targets
            .catalog_containers_by_ids(&containers)
            .await
            .map_err(PostureError::unexpected)?
            .iter()
            .map(|view| (view.id, naming::of_container_view(view)))
            .collect();
        let name =
            |names: &[(i64, String)], id: i64| names.iter().find(|(key, _)| *key == id).map(|(_, name)| name.clone());

        let mut details: Vec<(String, Detail)> = Vec::new();
        for row in rows {
            let index = match details.iter().position(|(name, _)| *name == row.package_name) {
                Some(index) => index,
                None => {
                    details.push((row.package_name.clone(), Detail::default()));
                    details.len().saturating_sub(1)
                }
            };
            let Some((_, detail)) = details.get_mut(index) else { continue };
            add(&mut detail.cves, row.identifier.clone());
            for version in versions::split(row.fix_versions.as_deref()) {
                add(&mut detail.fix_versions, version);
            }
            let repository = row.repo_id.and_then(|id| name(&repository_names, id));
            let container = row.container_id.and_then(|id| name(&container_names, id));
            if let Some(named) = repository.or(container) {
                add(&mut detail.target_names, named);
            }
        }
        Ok(details)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(severity: Option<&str>, type_: &str, c: i64) -> SeverityTypeCount {
        SeverityTypeCount { severity: severity.map(str::to_owned), type_: type_.to_owned(), c }
    }

    #[test]
    fn each_family_is_costed_and_those_on_request_are_not() {
        let tallies = SecurityDebt::tally(&[
            count(Some("critical"), "vulnerability", 2),
            count(Some("low"), "vulnerability", 5),
            count(Some("HIGH"), "secret", 1),
            count(Some("medium"), "sast", 2),
            count(None, "quality", 1),
            count(Some("low"), "iac", 3),
            count(Some("negligible"), "license", 1),
            count(Some("high"), "eol", 1),
            count(Some("critical"), "ai_review", 9),
            count(Some("critical"), "plugin", 9),
            count(Some("high"), "something_new", 1),
        ]);
        assert_eq!((tallies.total, tallies.critical, tallies.high, tallies.medium, tallies.low), (17, 2, 3, 2, 10));
        assert_eq!(tallies.vulnerability_hours, 2.0 * 1.5 + 5.0 * 0.8 + 1.5);
        assert_eq!(tallies.secret_hours, 2.0);
        assert_eq!(tallies.source_code_hours, 7.5);
        assert_eq!(tallies.iac_hours, 3.0);
        assert_eq!(tallies.license_hours, 3.0);
        assert_eq!(tallies.eol_hours, 4.0);
    }

    #[test]
    fn leverage_is_what_a_fix_closes_over_its_effort() {
        let weight = PackageWeight {
            package_name: "log4j".to_owned(),
            version: None,
            distinct_identifiers: 4,
            critical_count: 2,
            high_count: 1,
        };
        assert_eq!(effort_of(&weight), 1.4);
        assert_eq!(leverage_of(&weight), 11.1);
    }
}
