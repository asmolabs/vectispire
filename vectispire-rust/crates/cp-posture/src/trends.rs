//! The backlog over time — `common.domain.trends`: [`BacklogTrend`], the dashboard's and the weekly report's series,
//! and [`PostureTrendAnalytics`], the posture page's window and scoreboard.
//!
//! **All the date arithmetic is here, not in SQL**: the engines spell date truncation each their own way, and the
//! database returns two instants per issue. Every comparison is the Java one, strict or not as written there — the two
//! series differ on purpose in whether an issue resolved at midnight is still open that day.

use serde::Serialize;
use time::{Date, Duration, OffsetDateTime, Time};

use crate::arithmetic;
use crate::scorecard::SecurityGrade;

const SECONDS_PER_DAY: f64 = 86_400.0;

/// The instant a day starts, in UTC.
fn start_of(day: Date) -> OffsetDateTime {
    day.with_time(Time::MIDNIGHT).assume_utc()
}

/// The day an instant falls on, in UTC.
pub fn day_of(instant: OffsetDateTime) -> Date {
    instant.to_offset(time::UtcOffset::UTC).date()
}

fn next(day: Date) -> Date {
    day.next_day().unwrap_or(day)
}

fn within(moment: OffsetDateTime, start: OffsetDateTime, end: OffsetDateTime) -> bool {
    moment >= start && moment < end
}

/// When an issue was first seen and when it was resolved — either may be missing in a row written by hand or an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifespan {
    pub first_seen: Option<OffsetDateTime>,
    pub resolved_at: Option<OffsetDateTime>,
}

/// One day of the series.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub day: Date,
    pub open: i64,
    pub opened: i64,
    pub resolved: i64,
}

/// The series and the mean behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct Series {
    pub points: Vec<Point>,
    /// Absent when nothing was resolved in the window — not zero, which would read as "fixed the day it appears".
    pub mean_days_to_resolve: Option<f64>,
    pub resolved_in_window: i32,
}

/// `BacklogTrend`.
#[derive(Debug, Clone, Copy)]
pub struct BacklogTrend;

impl BacklogTrend {
    /// `over(lifespans, from, to)`, both days included. The callers clamp the window, so `from` after `to` — Java's
    /// `IllegalArgumentException` — draws no day rather than failing a chart.
    pub fn over(lifespans: &[Lifespan], from: Date, to: Date) -> Series {
        let mut points = Vec::new();
        let mut day = from;
        while day <= to {
            let start = start_of(day);
            let end = start_of(next(day));
            let (mut open, mut opened, mut resolved) = (0i64, 0i64, 0i64);
            for issue in lifespans {
                // A row with no first sighting cannot be placed on the axis.
                let Some(first_seen) = issue.first_seen else { continue };
                if within(first_seen, start, end) {
                    opened = opened.saturating_add(1);
                }
                if issue.resolved_at.is_some_and(|at| within(at, start, end)) {
                    resolved = resolved.saturating_add(1);
                }
                let seen_by_now = first_seen < end;
                let still_open = issue.resolved_at.is_none_or(|at| at >= end);
                if seen_by_now && still_open {
                    open = open.saturating_add(1);
                }
            }
            points.push(Point { day, open, opened, resolved });
            if day == Date::MAX {
                break;
            }
            day = next(day);
        }
        Series {
            points,
            mean_days_to_resolve: Self::mean_days_to_resolve(lifespans, from, to),
            resolved_in_window: Self::resolved_in(lifespans, from, to),
        }
    }

    fn resolved_within<'a>(
        lifespans: &'a [Lifespan],
        from: Date,
        to: Date,
    ) -> impl Iterator<Item = (OffsetDateTime, OffsetDateTime)> + 'a {
        let start = start_of(from);
        let end = start_of(next(to));
        lifespans.iter().filter_map(move |issue| match (issue.first_seen, issue.resolved_at) {
            (Some(first_seen), Some(resolved)) if within(resolved, start, end) => Some((first_seen, resolved)),
            _ => None,
        })
    }

    fn mean_days_to_resolve(lifespans: &[Lifespan], from: Date, to: Date) -> Option<f64> {
        let mut count = 0u32;
        let mut total_days = 0.0;
        for (first_seen, resolved) in Self::resolved_within(lifespans, from, to) {
            // Clamped at zero: a resolution before the first sighting is bad data, not an improvement.
            let seconds = arithmetic::seconds_between(first_seen, resolved).max(0);
            total_days += seconds as f64 / SECONDS_PER_DAY;
            count = count.saturating_add(1);
        }
        (count > 0).then(|| total_days / f64::from(count))
    }

    fn resolved_in(lifespans: &[Lifespan], from: Date, to: Date) -> i32 {
        i32::try_from(Self::resolved_within(lifespans, from, to).count()).unwrap_or(i32::MAX)
    }
}

/// An issue as the posture page reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueObservation {
    pub target_id: Option<i64>,
    pub target_kind: String,
    pub target_name: String,
    pub severity: String,
    pub first_seen: Option<OffsetDateTime>,
    pub resolved_at: Option<OffsetDateTime>,
}

/// One day of the posture page's curve.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DailyPosturePoint {
    #[serde(serialize_with = "iso_date")]
    pub date: Date,
    pub open_backlog: i64,
    pub newly_discovered: i64,
    pub newly_resolved: i64,
    pub rolling_mttr_days: Option<f64>,
}

/// One row of the maturity ranking.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetMaturityScore {
    pub target_id: Option<i64>,
    pub target_kind: String,
    pub target_name: String,
    pub open_critical: i64,
    pub open_high: i64,
    pub open_medium: i64,
    pub open_low: i64,
    pub total_resolved: i64,
    pub target_mttr_days: Option<f64>,
    pub security_score: Option<i32>,
    pub maturity_grade: SecurityGrade,
    pub risk_points: Option<f64>,
}

/// `PostureTrendAnalytics`, as the wire spells it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostureTrendAnalytics {
    pub window_days: i32,
    pub overall_mttr_days: Option<f64>,
    /// Sorted by severity name — the Java side's `TreeMap`.
    pub mttr_by_severity: serde_json::Map<String, serde_json::Value>,
    pub total_opened_in_window: i64,
    pub total_resolved_in_window: i64,
    pub net_resolution_rate_percentage: f64,
    pub daily_series: Vec<DailyPosturePoint>,
    pub target_scoreboard: Vec<TargetMaturityScore>,
}

fn iso_date<S: serde::Serializer>(date: &Date, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&iso(*date))
}

/// `LocalDate.toString` for the years this product meets: `2026-03-01`.
pub fn iso(date: Date) -> String {
    format!("{:04}-{:02}-{:02}", date.year(), u8::from(date.month()), date.day())
}

impl PostureTrendAnalytics {
    /// `now − windowDays` days.
    pub fn window_start(window_days: i32, now: OffsetDateTime) -> OffsetDateTime {
        now.saturating_sub(Duration::days(i64::from(window_days)))
    }

    /// Whether an issue can move a point of the window: unresolved, resolved in it, or seen in it.
    pub fn touches_window(observation: &IssueObservation, window_start: OffsetDateTime) -> bool {
        observation.resolved_at.is_none_or(|at| at >= window_start)
            || observation.first_seen.is_some_and(|at| at >= window_start)
    }

    /// `roundDays`: one decimal, a half rounded up.
    pub fn round_days(days: f64) -> f64 {
        arithmetic::tenths(days)
    }

    fn average(values: &[f64]) -> Option<f64> {
        if values.is_empty() {
            return None;
        }
        let sum: f64 = values.iter().sum();
        Some(Self::round_days(sum / values.len() as f64))
    }

    /// `calculate`: the window's MTTR, its totals, its daily series, and the scoreboard handed in.
    pub fn calculate(
        window_days: i32,
        now: OffsetDateTime,
        issues: &[IssueObservation],
        scoreboard: Vec<TargetMaturityScore>,
    ) -> PostureTrendAnalytics {
        let window_start = Self::window_start(window_days, now);
        let start_date = day_of(window_start);
        let end_date = day_of(now);

        let mut by_severity: std::collections::BTreeMap<String, Vec<f64>> = std::collections::BTreeMap::new();
        let mut all = Vec::new();
        let mut total_opened = 0i64;
        let mut total_resolved = 0i64;
        for observation in issues {
            if let (Some(resolved), Some(first_seen)) = (observation.resolved_at, observation.first_seen)
                && resolved > first_seen
                && resolved >= window_start
            {
                let days = arithmetic::seconds_between(first_seen, resolved) as f64 / SECONDS_PER_DAY;
                total_resolved = total_resolved.saturating_add(1);
                all.push(days);
                // `toUpperCase(Locale.ROOT)` of a severity the database holds.
                by_severity
                    .entry(vectispire_domain::java::to_upper_root(&observation.severity))
                    .or_default()
                    .push(days);
            }
            if observation.first_seen.is_some_and(|at| at >= window_start) {
                total_opened = total_opened.saturating_add(1);
            }
        }

        let mut mttr_by_severity = serde_json::Map::new();
        for (severity, days) in &by_severity {
            let value = Self::average(days).map_or(serde_json::Value::Null, serde_json::Value::from);
            mttr_by_severity.insert(severity.clone(), value);
        }

        let velocity = if total_opened > 0 {
            (total_resolved as f64 / total_opened as f64) * 100.0
        } else if total_resolved > 0 {
            100.0
        } else {
            0.0
        };

        let mut daily = Vec::new();
        let mut day = start_date;
        while day <= end_date {
            let start = start_of(day);
            let end = start_of(next(day));
            let (mut open, mut opened, mut resolved) = (0i64, 0i64, 0i64);
            let mut durations = Vec::new();
            for observation in issues {
                let seen_before_end = observation.first_seen.is_some_and(|at| at < end);
                // Strictly after: an issue resolved at midnight is closed on the day that ends then.
                let resolved_after_end = observation.resolved_at.is_none_or(|at| at > end);
                if seen_before_end && resolved_after_end {
                    open = open.saturating_add(1);
                }
                if observation.first_seen.is_some_and(|at| within(at, start, end)) {
                    opened = opened.saturating_add(1);
                }
                if let Some(at) = observation.resolved_at
                    && within(at, start, end)
                {
                    resolved = resolved.saturating_add(1);
                    if let Some(first_seen) = observation.first_seen {
                        durations.push(arithmetic::seconds_between(first_seen, at) as f64 / SECONDS_PER_DAY);
                    }
                }
            }
            daily.push(DailyPosturePoint {
                date: day,
                open_backlog: open,
                newly_discovered: opened,
                newly_resolved: resolved,
                rolling_mttr_days: Self::average(&durations),
            });
            if day == Date::MAX {
                break;
            }
            day = next(day);
        }

        PostureTrendAnalytics {
            window_days,
            overall_mttr_days: Self::average(&all),
            mttr_by_severity,
            total_opened_in_window: total_opened,
            total_resolved_in_window: total_resolved,
            net_resolution_rate_percentage: arithmetic::tenths(velocity),
            daily_series: daily,
            target_scoreboard: scoreboard,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(first_seen: i64, resolved_at: Option<i64>) -> IssueObservation {
        let at = |seconds: i64| OffsetDateTime::UNIX_EPOCH + Duration::days(20_000) + Duration::seconds(seconds);
        IssueObservation {
            target_id: Some(1),
            target_kind: "REPOSITORY".to_owned(),
            target_name: "r".to_owned(),
            severity: "HIGH".to_owned(),
            first_seen: Some(at(first_seen)),
            resolved_at: resolved_at.map(at),
        }
    }

    #[test]
    fn a_resolution_in_the_instant_of_its_sighting_is_no_resolution() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(20_001);
        let analytics = PostureTrendAnalytics::calculate(7, now, &[observation(3_600, Some(3_600))], Vec::new());
        assert_eq!((analytics.total_resolved_in_window, analytics.overall_mttr_days), (0, None));
    }

    #[test]
    fn a_sighting_in_the_window_touches_it_even_resolved_before_it() {
        // Bad data — resolved before it was seen — but seen in the window: Java keeps it on the curve.
        let start = OffsetDateTime::UNIX_EPOCH + Duration::days(20_000);
        assert!(PostureTrendAnalytics::touches_window(&observation(60, Some(-60)), start));
        assert!(!PostureTrendAnalytics::touches_window(&observation(-120, Some(-60)), start));
    }
}
