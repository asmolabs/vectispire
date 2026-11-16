//! The posture module's decisions against Java's answers in `reference/posture/decisions.json`
//! (`PostureReferenceSetTest`, in `vectispire-core`, written before this port): the grades, decision 0036's formula over
//! a grid of backlogs and weights and the weights it refuses, the coverage cap, the badge, the backlog series, the
//! posture analytics, the remediation distribution and coverage, the recommended version and the weekly report.
//! Every difference is collected and reported at once.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeMap;

use serde_json::{Value, json};
use time::{Date, OffsetDateTime};
use vectispire_cp_issues::RemediationSla;
use vectispire_cp_posture::digest::{DigestCounts, PostureDigest};
use vectispire_cp_posture::remediation::{Open, OpenFamily, RemediationCoverage, RemediationDistribution, Resolved};
use vectispire_cp_posture::scorecard::{CandidateScore, Counts, SecurityGrade, Weights, badge};
use vectispire_cp_posture::trends::{BacklogTrend, IssueObservation, Lifespan, PostureTrendAnalytics, iso};
use vectispire_cp_posture::{coverage, versions};
use vectispire_domain::Severity;

fn decisions() -> Value {
    vectispire_testkit::read_json("posture/decisions.json")
}

fn check(differences: &mut Vec<String>, what: &str, expected: &Value, got: &Value) {
    if !same(expected, got) {
        differences.push(format!("{what}: Java {expected}, Rust {got}"));
    }
}

/// Equal as JSON, numbers compared as the doubles they denote — Jackson writes `100` for a long and `100.0` for a
/// double, and the reference holds both.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(l, r)| same(l, r)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|((kl, vl), (kr, vr))| kl == kr && same(vl, vr))
        }
        _ => a == b,
    }
}

fn report(differences: Vec<String>) {
    assert!(differences.is_empty(), "{} differences from Java:\n{}", differences.len(), differences.join("\n"));
}

fn instant(value: &Value) -> Option<OffsetDateTime> {
    value.as_str().map(|text| OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap())
}

fn date(text: &str) -> Date {
    let parts: Vec<i32> = text.split('-').map(|part| part.parse().unwrap()).collect();
    let month = time::Month::try_from(u8::try_from(parts[1]).unwrap()).unwrap();
    Date::from_calendar_date(parts[0], month, u8::try_from(parts[2]).unwrap()).unwrap()
}

fn nullable(value: Option<f64>) -> Value {
    value.map_or(Value::Null, Value::from)
}

#[test]
fn grades_and_their_labels() {
    let set = decisions();
    let mut differences = Vec::new();
    for row in set["grades"].as_array().unwrap() {
        let score = i32::try_from(row["score"].as_i64().unwrap()).unwrap();
        check(
            &mut differences,
            &format!("grade of {score}"),
            &row["grade"],
            &json!(SecurityGrade::from_score(score).name()),
        );
    }
    for (row, grade) in set["gradeLabels"].as_array().unwrap().iter().zip(SecurityGrade::ALL) {
        let got = json!({ "grade": grade.name(), "label": grade.label(), "badgeColor": grade.badge_color() });
        check(&mut differences, "grade label", row, &got);
    }
    report(differences);
}

fn weights_of(row: &Value) -> [f64; 7] {
    let values: Vec<f64> = row
        .as_array()
        .unwrap()
        .iter()
        .map(|value| match value {
            Value::Number(number) => number.as_f64().unwrap(),
            Value::String(text) => match text.as_str() {
                "NaN" => f64::NAN,
                "Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                other => other.parse().unwrap(),
            },
            other => panic!("not a weight: {other}"),
        })
        .collect();
    values.try_into().unwrap()
}

#[test]
fn the_formula_over_a_grid_of_backlogs_and_weights() {
    let set = decisions();
    let mut differences = Vec::new();
    for row in set["candidateScores"].as_array().unwrap() {
        let [exploited, critical, high, medium, low, licence, k] = weights_of(&row["weights"]);
        let weights = Weights::new(exploited, critical, high, medium, low, licence, k).unwrap();
        let c: Vec<i64> = row["counts"].as_array().unwrap().iter().map(|v| v.as_i64().unwrap()).collect();
        let counts = Counts { exploited: c[0], critical: c[1], high: c[2], medium: c[3], low: c[4], licences: c[5] };
        let result = CandidateScore::of(&counts, &weights);
        let got = json!({
            "weights": row["weights"],
            "counts": row["counts"],
            "score": result.score,
            "grade": result.grade.name(),
            "riskPoints": result.risk_points,
            "exact": CandidateScore::exact(&counts, &weights),
        });
        check(&mut differences, "candidate score", row, &got);
    }
    for row in set["refusedWeights"].as_array().unwrap() {
        let [exploited, critical, high, medium, low, licence, k] = weights_of(&row["weights"]);
        let refused = Weights::new(exploited, critical, high, medium, low, licence, k).err();
        check(&mut differences, &format!("weights {}", row["weights"]), &row["refused"], &json!(refused));
    }
    report(differences);
}

#[test]
fn the_coverage_cap() {
    let set = decisions();
    let mut differences = Vec::new();
    for row in set["coverageCap"].as_array().unwrap() {
        let field = |name: &str| i32::try_from(row[name].as_i64().unwrap()).unwrap();
        let capped = coverage::capped(field("score"), field("total"), field("observed"));
        check(&mut differences, &format!("cap {row}"), &row["capped"], &json!(capped));
    }
    report(differences);
}

#[test]
fn the_badge_byte_for_byte() {
    let set = decisions();
    let mut differences = Vec::new();
    for row in set["badges"].as_array().unwrap() {
        let svg = badge("security grade", row["status"].as_str().unwrap(), row["color"].as_str().unwrap());
        check(&mut differences, &format!("badge {}", row["status"]), &row["svg"], &json!(svg));
    }
    report(differences);
}

#[test]
fn the_backlog_series() {
    let set = decisions();
    let spans = spans();
    let lifespans: Vec<Lifespan> = spans
        .iter()
        .map(|(first_seen, resolved_at)| Lifespan { first_seen: *first_seen, resolved_at: *resolved_at })
        .collect();
    let mut differences = Vec::new();
    for row in set["backlogTrend"].as_array().unwrap() {
        let series =
            BacklogTrend::over(&lifespans, date(row["from"].as_str().unwrap()), date(row["to"].as_str().unwrap()));
        let got = json!({
            "from": row["from"],
            "to": row["to"],
            "points": series.points.iter().map(|point| json!({
                "day": iso(point.day), "open": point.open, "opened": point.opened, "resolved": point.resolved,
            })).collect::<Vec<_>>(),
            "meanDaysToResolve": nullable(series.mean_days_to_resolve),
            "resolvedInWindow": series.resolved_in_window,
        });
        check(&mut differences, "backlog series", row, &got);
    }
    report(differences);
}

/// The test's `SPANS`, repeated here as the Java test spells them — the reference holds the answers, not the inputs.
fn spans() -> Vec<(Option<OffsetDateTime>, Option<OffsetDateTime>)> {
    let at = |text: Option<&str>| instant(&json!(text));
    [
        (Some("2026-03-01T10:00:00Z"), None),
        (Some("2026-03-02T00:00:00Z"), Some("2026-03-04T00:00:00Z")),
        (Some("2026-03-03T23:59:59.999999999Z"), Some("2026-03-04T00:00:00Z")),
        (Some("2026-02-20T08:30:00Z"), Some("2026-03-05T12:00:00.5Z")),
        (Some("2026-03-05T12:00:00Z"), Some("2026-03-05T11:00:00Z")),
        (None, Some("2026-03-05T00:00:00Z")),
        (Some("2026-03-06T00:00:00Z"), None),
        (Some("2026-01-01T00:00:00Z"), Some("2026-02-01T00:00:00Z")),
        (Some("2026-03-07T23:00:00Z"), Some("2026-03-08T00:00:00Z")),
        (Some("2026-03-01T00:00:00.000000001Z"), Some("2026-03-07T17:45:12.25Z")),
    ]
    .into_iter()
    .map(|(first, resolved)| (at(first), at(resolved)))
    .collect()
}

const SEVERITIES: [Option<&str>; 10] = [
    Some("critical"),
    Some("HIGH"),
    None,
    Some("Medium"),
    Some("low"),
    Some("critical"),
    Some("unknown"),
    Some("high"),
    Some("LOW"),
    Some("weird"),
];

#[test]
fn the_posture_analytics() {
    let set = decisions();
    let observations: Vec<IssueObservation> = spans()
        .into_iter()
        .enumerate()
        .map(|(index, (first_seen, resolved_at))| IssueObservation {
            target_id: Some(i64::try_from(index % 3).unwrap()),
            target_kind: if index % 2 == 0 { "REPOSITORY" } else { "CONTAINER" }.to_owned(),
            target_name: format!("target {}", index % 3),
            // `DashboardQueryService` reads a missing severity as MEDIUM before this; the test hands `null` over as it is,
            // which `calculate` files under UNKNOWN.
            severity: SEVERITIES[index].unwrap_or("UNKNOWN").to_owned(),
            first_seen,
            resolved_at,
        })
        .collect();
    let mut differences = Vec::new();
    for row in set["postureTrend"].as_array().unwrap() {
        if let Some(rounded) = row.get("roundDays") {
            for case in rounded.as_array().unwrap() {
                let days = case["days"].as_f64().unwrap();
                check(
                    &mut differences,
                    &format!("roundDays {days}"),
                    &case["rounded"],
                    &json!(PostureTrendAnalytics::round_days(days)),
                );
            }
            continue;
        }
        let window = i32::try_from(row["windowDays"].as_i64().unwrap()).unwrap();
        let now = instant(&row["now"]).unwrap();
        let start = PostureTrendAnalytics::window_start(window, now);
        let touching: Vec<usize> = (0..observations.len())
            .filter(|index| PostureTrendAnalytics::touches_window(&observations[*index], start))
            .collect();
        let issues: Vec<IssueObservation> = touching.iter().map(|index| observations[*index].clone()).collect();
        let analytics = PostureTrendAnalytics::calculate(window, now, &issues, Vec::new());
        let got = json!({
            "windowDays": window,
            "now": row["now"],
            "touching": touching,
            "overallMttrDays": nullable(analytics.overall_mttr_days),
            "mttrBySeverity": analytics.mttr_by_severity,
            "totalOpenedInWindow": analytics.total_opened_in_window,
            "totalResolvedInWindow": analytics.total_resolved_in_window,
            "netResolutionRatePercentage": analytics.net_resolution_rate_percentage,
            "dailySeries": analytics.daily_series.iter().map(|point| json!({
                "date": iso(point.date),
                "openBacklog": point.open_backlog,
                "newlyDiscovered": point.newly_discovered,
                "newlyResolved": point.newly_resolved,
                "rollingMttrDays": nullable(point.rolling_mttr_days),
            })).collect::<Vec<_>>(),
        });
        check(&mut differences, &format!("analytics {window} days to {}", row["now"]), row, &got);
    }
    report(differences);
}

fn distribution_json(distribution: &RemediationDistribution) -> Value {
    json!({
        "windowDays": distribution.window_days,
        "bySeverity": distribution.by_severity.iter().map(|line| json!({
            "severity": line.severity.wire_name(),
            "windowDays": line.window_days,
            "withinSla": line.within_sla,
            "late": line.late,
            "percentageWithinSla": nullable(line.percentage_within_sla),
            "medianDays": nullable(line.median_days),
            "ninetiethDays": nullable(line.ninetieth_days),
            "openOverdue": line.open_overdue,
            "oldestOpenDays": line.oldest_open_days,
        })).collect::<Vec<_>>(),
        "oldestOpenDays": distribution.oldest_open_days,
        "oldestOpenSeverity": distribution.oldest_open_severity.map(Severity::wire_name),
    })
}

#[test]
fn the_remediation_distribution() {
    let set = decisions();
    let day = 86_400;
    let mut windows = BTreeMap::new();
    windows.insert(Severity::Critical, time::Duration::days(15));
    windows.insert(Severity::High, time::Duration::days(30));
    windows.insert(Severity::Medium, time::Duration::days(0));
    windows.insert(Severity::Low, time::Duration::days(180));
    let sla = RemediationSla::new(windows);
    let resolved = [
        (Some(Severity::Critical), 3 * day),
        (Some(Severity::Critical), 15 * day),
        (Some(Severity::Critical), 15 * day + 1),
        (Some(Severity::Critical), 40 * day + 4321),
        (Some(Severity::High), 1),
        (Some(Severity::Medium), 100 * day),
        (Some(Severity::Unknown), 2 * day),
        (Some(Severity::Low), 7 * day + 43_200),
        (Some(Severity::Low), 9 * day),
        (Some(Severity::Low), 181 * day),
        (None, day),
    ]
    .map(|(severity, seconds)| Resolved { severity, seconds });
    let open = [
        Open { severity: Some(Severity::Critical), total: 4, overdue: 2, oldest_days: Some(31) },
        Open { severity: Some(Severity::High), total: 1, overdue: 0, oldest_days: Some(2) },
        Open { severity: Some(Severity::Low), total: 9, overdue: 1, oldest_days: Some(31) },
        Open { severity: Some(Severity::Negligible), total: 3, overdue: 0, oldest_days: None },
    ];
    let cases = [
        RemediationDistribution::calculate(30, &sla, &resolved, &open),
        RemediationDistribution::calculate(7, &RemediationSla::default_policy(), &[], &[]),
        RemediationDistribution::calculate(90, &RemediationSla::default_policy(), &resolved[..5], &open[1..2]),
    ];
    let mut differences = Vec::new();
    for (row, distribution) in set["remediationDistribution"].as_array().unwrap().iter().zip(&cases) {
        check(&mut differences, "distribution", row, &distribution_json(distribution));
    }
    report(differences);
}

#[test]
fn the_remediation_coverage() {
    let set = decisions();
    let mut differences = Vec::new();
    for row in set["remediationCoverage"].as_array().unwrap() {
        let families: Vec<OpenFamily> = row["families"]
            .as_array()
            .unwrap()
            .iter()
            .map(|family| OpenFamily {
                type_: family["type"].as_str().unwrap().to_owned(),
                package_named: family["packageNamed"].as_i64().unwrap(),
                unnamed: family["unnamed"].as_i64().unwrap(),
            })
            .collect();
        let coverage = RemediationCoverage::of(&families);
        let got = json!({
            "families": row["families"],
            "openFindings": coverage.open_findings,
            "addressableByUpgrade": coverage.addressable_by_upgrade,
            "beyondUpgrades": coverage.beyond_upgrades,
            "gaps": coverage.gaps,
        });
        check(&mut differences, "coverage", row, &got);
    }
    report(differences);
}

#[test]
fn the_version_a_fix_recommends() {
    let set = decisions();
    let mut differences = Vec::new();
    for row in set["versions"].as_array().unwrap() {
        if let Some(candidates) = row.get("candidates") {
            let candidates: Vec<&str> = candidates.as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
            let highest = versions::highest(candidates.iter().copied());
            check(&mut differences, &format!("highest of {candidates:?}"), &row["highest"], &json!(highest));
        } else {
            let parts = versions::split(row["split"].as_str());
            check(&mut differences, &format!("split {}", row["split"]), &row["parts"], &json!(parts));
        }
    }
    report(differences);
}

#[test]
fn the_weekly_report() {
    let set = decisions();
    let mut differences = Vec::new();
    for row in set["digest"].as_array().unwrap() {
        let counts = DigestCounts {
            open_total: row["openTotal"].as_i64().unwrap(),
            backlog_by_severity: row["backlogBySeverity"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(severity, count)| (severity.clone(), count.as_i64().unwrap()))
                .collect(),
            opened_this_week: row["openedThisWeek"].as_i64().unwrap(),
            resolved_this_week: row["resolvedThisWeek"].as_i64().unwrap(),
            overdue_count: row["overdueCount"].as_i64().unwrap(),
            failing_targets: i32::try_from(row["failingTargets"].as_i64().unwrap()).unwrap(),
            total_targets: i32::try_from(row["totalTargets"].as_i64().unwrap()).unwrap(),
            never_scanned: row["neverScanned"].as_i64().unwrap(),
            last_scan_failed: row["lastScanFailed"].as_i64().unwrap(),
            mean_days_to_resolve: row["meanDaysToResolve"].as_f64(),
        };
        let digest = PostureDigest::of(date(row["weekOf"].as_str().unwrap()), &counts);
        let week = row["weekOf"].as_str().unwrap();
        check(&mut differences, &format!("{week} text"), &row["text"], &json!(digest.text));
        check(&mut differences, &format!("{week} subject"), &row["subject"], &json!(digest.as_subject()));
        check(&mut differences, &format!("{week} plain text"), &row["plainText"], &json!(digest.as_plain_text()));
    }
    report(differences);
}
