//! What remediation takes — `common.domain.remediation`: the distribution of resolution times against the SLA
//! ([`RemediationDistribution`]), how much of the backlog an upgrade can close ([`RemediationCoverage`]), the debt
//! estimate ([`SecurityDebtReport`]) and the fixes that close the most ([`HighImpactFix`]).

use std::cmp::Reverse;
use std::collections::BTreeMap;

use serde::Serialize;
use vectispire_cp_issues::RemediationSla;
use vectispire_domain::finding_type::GateParticipation;
use vectispire_domain::{FindingType, Severity};

use crate::arithmetic;

const SECONDS_PER_DAY: f64 = 86_400.0;

/// The severities in their declaration order, as `Severity.values()` lists them.
pub const SEVERITIES: [Severity; 6] =
    [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Negligible, Severity::Unknown];

/// A resolution, and how long it took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    pub severity: Option<Severity>,
    pub seconds: i64,
}

/// The open backlog of one severity: how much, how much is late, and the age of its oldest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Open {
    pub severity: Option<Severity>,
    pub total: i64,
    pub overdue: i64,
    pub oldest_days: Option<i64>,
}

/// One severity's line.
#[derive(Debug, Clone, PartialEq)]
pub struct BySeverity {
    pub severity: Severity,
    pub window_days: i32,
    pub within_sla: i64,
    pub late: i64,
    pub percentage_within_sla: Option<f64>,
    pub median_days: Option<f64>,
    pub ninetieth_days: Option<f64>,
    pub open_overdue: i64,
    pub oldest_open_days: Option<i64>,
}

/// `RemediationDistribution`.
#[derive(Debug, Clone, PartialEq)]
pub struct RemediationDistribution {
    pub window_days: i32,
    pub by_severity: Vec<BySeverity>,
    pub oldest_open_days: Option<i64>,
    pub oldest_open_severity: Option<Severity>,
}

impl RemediationDistribution {
    /// `calculate`: a line per severity, in declaration order, whatever the backlog holds.
    pub fn calculate(window_days: i32, sla: &RemediationSla, resolved: &[Resolved], open: &[Open]) -> Self {
        let mut seconds_by_severity: BTreeMap<Severity, Vec<i64>> = BTreeMap::new();
        for item in resolved {
            if let Some(severity) = item.severity {
                seconds_by_severity.entry(severity).or_default().push(item.seconds);
            }
        }
        // `EnumMap.put`: the last row of a severity wins.
        let mut open_by_severity: BTreeMap<Severity, Open> = BTreeMap::new();
        for row in open {
            if let Some(severity) = row.severity {
                open_by_severity.insert(severity, *row);
            }
        }

        let mut rows = Vec::new();
        for severity in SEVERITIES {
            let seconds = seconds_by_severity.get(&severity).map(Vec::as_slice).unwrap_or_default();
            let backlog = open_by_severity.get(&severity);
            let deadline = sla.window_for(severity).map_or(0, |window| window.whole_seconds());
            let (mut within, mut late) = (0i64, 0i64);
            for value in seconds {
                if deadline > 0 && *value > deadline {
                    late = late.saturating_add(1);
                } else {
                    within = within.saturating_add(1);
                }
            }
            rows.push(BySeverity {
                severity,
                window_days: i32::try_from(deadline / 86_400).unwrap_or(i32::MAX),
                within_sla: within,
                late,
                // No deadline is no percentage: 100 % against a window nobody set is a claim earned by nothing.
                percentage_within_sla: (deadline != 0 && !seconds.is_empty())
                    .then(|| arithmetic::tenths((100.0 * within as f64) / seconds.len() as f64)),
                median_days: percentile(seconds, 50),
                ninetieth_days: percentile(seconds, 90),
                open_overdue: backlog.map_or(0, |row| row.overdue),
                oldest_open_days: backlog.and_then(|row| row.oldest_days),
            });
        }

        // `Stream.max`: of two equally old, the first listed.
        let mut worst: Option<&Open> = None;
        for row in open {
            if let Some(days) = row.oldest_days
                && worst.and_then(|current| current.oldest_days).is_none_or(|current| days > current)
            {
                worst = Some(row);
            }
        }
        RemediationDistribution {
            window_days,
            by_severity: rows,
            oldest_open_days: worst.and_then(|row| row.oldest_days),
            oldest_open_severity: worst.and_then(|row| row.severity),
        }
    }
}

fn percentile(seconds: &[i64], percentile: i32) -> Option<f64> {
    if seconds.is_empty() {
        return None;
    }
    let mut sorted = seconds.to_vec();
    sorted.sort_unstable();
    // `(int) Math.ceil(p / 100.0 * n)`: at most n, a count of rows, so the cast is exact.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let rank = ((f64::from(percentile) / 100.0) * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len().saturating_sub(1));
    sorted.get(index).map(|value| arithmetic::tenths(*value as f64 / SECONDS_PER_DAY))
}

/// A family of findings no upgrade closes, and how many.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemediationGap {
    pub family: String,
    pub findings: i64,
}

/// The open findings of one type, by whether they name a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFamily {
    pub type_: String,
    pub package_named: i64,
    pub unnamed: i64,
}

/// How much of the open backlog an upgrade can close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationCoverage {
    pub open_findings: i64,
    pub addressable_by_upgrade: i64,
    pub beyond_upgrades: i64,
    pub gaps: Vec<RemediationGap>,
}

impl RemediationCoverage {
    /// The family of vulnerabilities naming no package.
    pub const UNPACKAGED: &'static str = "unpackaged";

    /// `of`: a vulnerability naming a package is addressable; everything else is a gap, by family. The types that
    /// take part in the gate only on request (AI review, plugins, imports) are not in the plan at all.
    pub fn of(families: &[OpenFamily]) -> Self {
        let (mut addressable, mut beyond) = (0i64, 0i64);
        let mut gaps = Vec::new();
        for family in families {
            if FindingType::from_wire_name(Some(&family.type_))
                .is_some_and(|kind| kind.gate_participation() == GateParticipation::OnRequest)
            {
                continue;
            }
            if family.type_ == FindingType::Vulnerability.wire_name() {
                addressable = addressable.saturating_add(family.package_named);
                if family.unnamed > 0 {
                    beyond = beyond.saturating_add(family.unnamed);
                    gaps.push(RemediationGap { family: Self::UNPACKAGED.to_owned(), findings: family.unnamed });
                }
                continue;
            }
            let all = family.package_named.saturating_add(family.unnamed);
            if all > 0 {
                beyond = beyond.saturating_add(all);
                gaps.push(RemediationGap { family: family.type_.clone(), findings: all });
            }
        }
        gaps.sort_by(|a, b| {
            Reverse(a.findings)
                .cmp(&Reverse(b.findings))
                .then_with(|| vectispire_domain::java::compare_utf16(&a.family, &b.family))
        });
        RemediationCoverage {
            open_findings: addressable.saturating_add(beyond),
            addressable_by_upgrade: addressable,
            beyond_upgrades: beyond,
            gaps,
        }
    }
}

/// An upgrade, and what it closes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HighImpactFix {
    pub package_name: String,
    pub current_version: String,
    /// The highest version the findings say fixes it; absent when none announces a fix.
    pub recommended_version: Option<String>,
    pub cve_count_resolved: i64,
    pub critical_cve_count: i64,
    pub high_cve_count: i64,
    pub estimated_hours: f64,
    pub leverage_score: f64,
    pub affected_cves: Vec<String>,
    pub affected_target_names: Vec<String>,
}

/// The debt estimate, as `SecurityDebtReportView` spells it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityDebtReport {
    pub total_open_issues: i64,
    pub critical_issues: i64,
    pub high_issues: i64,
    pub medium_issues: i64,
    pub low_issues: i64,
    pub total_estimated_hours: f64,
    pub total_estimated_person_days: f64,
    pub vulnerabilities_debt_hours: f64,
    pub secrets_debt_hours: f64,
    pub sast_debt_hours: f64,
    pub iac_debt_hours: f64,
    pub license_debt_hours: f64,
    pub eol_debt_hours: f64,
    pub top_high_impact_fixes: Vec<HighImpactFix>,
}
