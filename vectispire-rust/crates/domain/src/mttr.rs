//! Mean time to remediate across resolved issues — Java's `MttrCalculator`.
//!
//! Days are whole hours floored to days, at least one, as `Duration.toHours() / 24` then `Math.max(1, …)`; each mean
//! is rounded to a tenth with `Math.round` (half towards positive infinity). The breakdown lists the severities most
//! severe first — the `EnumMap`'s order, which Java now hands out as it is rather than through `Map.copyOf`, whose
//! order was salted per JVM.

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::instant::Instant;
use crate::java_math::tenths;
use crate::severity::Severity;

/// One resolved issue — `ResolvedIssue`. One missing date, or a resolution before the first sighting, is left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedIssue {
    pub severity: Option<Severity>,
    pub first_seen_at: Option<Instant>,
    pub resolved_at: Option<Instant>,
}

/// `MttrResult`: the mean per severity in days, the overall mean (absent when nothing counted) and how many counted.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MttrResult {
    #[serde(serialize_with = "by_severity_name")]
    pub mttr_by_severity_days: Vec<(Severity, f64)>,
    pub overall_mttr_days: Option<f64>,
    pub resolved_count: i32,
}

/// The map Jackson writes for an `EnumMap<Severity, Double>`: the constants' names as keys, in the enum's order.
fn by_severity_name<S: Serializer>(entries: &[(Severity, f64)], serializer: S) -> Result<S::Ok, S::Error> {
    let mut map = serializer.serialize_map(Some(entries.len()))?;
    for (severity, days) in entries {
        map.serialize_entry(&severity.wire_name().to_ascii_uppercase(), days)?;
    }
    map.end()
}

/// `calculate`.
pub fn calculate(resolved: &[ResolvedIssue]) -> MttrResult {
    let mut by_severity: std::collections::BTreeMap<Severity, (i64, i64)> = std::collections::BTreeMap::new();
    let mut total_days = 0i64;
    let mut valid = 0i32;
    for issue in resolved {
        let (Some(first_seen), Some(resolved_at)) = (issue.first_seen_at, issue.resolved_at) else {
            continue;
        };
        if resolved_at < first_seen {
            continue;
        }
        let days = (whole_hours(first_seen, resolved_at) / 24).max(1);
        total_days = total_days.wrapping_add(days);
        valid = valid.wrapping_add(1);
        if let Some(severity) = issue.severity {
            let (sum, count) = by_severity.entry(severity).or_insert((0, 0));
            *sum = sum.wrapping_add(days);
            *count = count.wrapping_add(1);
        }
    }
    if valid == 0 {
        return MttrResult { mttr_by_severity_days: Vec::new(), overall_mttr_days: None, resolved_count: 0 };
    }
    // `LongStream.average()`: the `long` sum over the count, in `double`.
    let mttr_by_severity_days =
        by_severity.into_iter().map(|(severity, (sum, count))| (severity, tenths(sum as f64 / count as f64))).collect();
    MttrResult {
        mttr_by_severity_days,
        overall_mttr_days: Some(tenths(total_days as f64 / f64::from(valid))),
        resolved_count: valid,
    }
}

/// `Duration.between(from, to).toHours()` for `to` not before `from`: whole seconds, a borrowed second when the
/// nanoseconds go backwards, then whole hours.
fn whole_hours(from: Instant, to: Instant) -> i64 {
    let borrow = i64::from(to.nano < from.nano);
    to.epoch_second.wrapping_sub(from.epoch_second).wrapping_sub(borrow) / 3_600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_the_mean_by_severity_and_overall() {
        // `MttrCalculatorTest.calculatesMttr`.
        let now = Instant::of_epoch_second(1_787_392_800);
        let issue = |severity, days: i64| ResolvedIssue {
            severity: Some(severity),
            first_seen_at: now.minus_days(days),
            resolved_at: Some(now),
        };
        let result = calculate(&[
            issue(Severity::Critical, 5),
            issue(Severity::Critical, 7),
            issue(Severity::High, 12),
            issue(Severity::High, 20),
        ]);
        assert_eq!(result.resolved_count, 4);
        assert_eq!(result.mttr_by_severity_days, vec![(Severity::Critical, 6.0), (Severity::High, 16.0)]);
        assert_eq!(result.overall_mttr_days, Some(11.0));
        assert_eq!(calculate(&[]).overall_mttr_days, None);
    }
}
