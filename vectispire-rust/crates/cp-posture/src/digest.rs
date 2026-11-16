//! The weekly posture report's content — `common.domain.notifications.PostureDigest`: the webhook's JSON, the mail's
//! subject and its plain text. Sending it is the notifications module's ([`crate::DigestChannels`]).

use serde::Serialize;
use time::Date;

use crate::arithmetic;
use crate::trends::iso;

/// What the report counts.
#[derive(Debug, Clone, PartialEq)]
pub struct DigestCounts {
    pub open_total: i64,
    /// In the order handed over: most severe first, the severities with nothing open left out.
    pub backlog_by_severity: Vec<(String, i64)>,
    pub opened_this_week: i64,
    pub resolved_this_week: i64,
    pub overdue_count: i64,
    pub failing_targets: i32,
    pub total_targets: i32,
    pub never_scanned: i64,
    pub last_scan_failed: i64,
    pub mean_days_to_resolve: Option<f64>,
}

/// The report, as the webhook receives it (`@JsonInclude(NON_NULL)`: no mean is no field).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PostureDigest {
    pub text: String,
    pub week_of: String,
    pub open_total: i64,
    pub backlog_by_severity: serde_json::Map<String, serde_json::Value>,
    pub opened_this_week: i64,
    pub resolved_this_week: i64,
    pub overdue_count: i64,
    pub failing_targets: i32,
    pub total_targets: i32,
    pub never_scanned: i64,
    pub last_scan_failed: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_days_to_resolve: Option<f64>,
}

impl PostureDigest {
    /// `of(weekStarting, counts)`.
    pub fn of(week_starting: Date, counts: &DigestCounts) -> PostureDigest {
        let mut backlog = serde_json::Map::new();
        for (severity, count) in &counts.backlog_by_severity {
            backlog.insert(severity.clone(), serde_json::Value::from(*count));
        }
        PostureDigest {
            text: summary(week_starting, counts),
            week_of: iso(week_starting),
            open_total: counts.open_total,
            backlog_by_severity: backlog,
            opened_this_week: counts.opened_this_week,
            resolved_this_week: counts.resolved_this_week,
            overdue_count: counts.overdue_count,
            failing_targets: counts.failing_targets,
            total_targets: counts.total_targets,
            never_scanned: counts.never_scanned,
            last_scan_failed: counts.last_scan_failed,
            mean_days_to_resolve: counts.mean_days_to_resolve,
        }
    }

    /// The mail's body.
    pub fn as_plain_text(&self) -> String {
        let mut body = format!("{}\n\nOpen issues by severity\n", self.text);
        if self.backlog_by_severity.is_empty() {
            body.push_str("  none\n");
        } else {
            for (severity, count) in &self.backlog_by_severity {
                body.push_str(&format!("  {severity}: {count}\n"));
            }
        }
        body.push('\n');
        body.push_str(&format!("Appeared this week: {}\n", self.opened_this_week));
        body.push_str(&format!("Resolved this week: {}\n", self.resolved_this_week));
        body.push_str(&format!("Past their deadline: {}\n", self.overdue_count));
        // Absent rather than "0 days", which would read as "fixed the day it appears".
        let mean = self
            .mean_days_to_resolve
            .map_or_else(|| "no issue was resolved this week".to_owned(), |mean| arithmetic::fixed(mean, 1));
        body.push_str(&format!("Mean days to resolve: {mean}\n"));
        body.push('\n');
        body.push_str(&format!("Targets failing the gate: {} of {}\n", self.failing_targets, self.total_targets));
        body.push_str(&format!("Never scanned: {}\n", self.never_scanned));
        body.push_str(&format!("Last scan failed: {}\n", self.last_scan_failed));
        body
    }

    /// The mail's subject.
    pub fn as_subject(&self) -> String {
        let late = if self.overdue_count > 0 { format!(", {} late", self.overdue_count) } else { String::new() };
        format!("Vectispire — week of {}: {} open{late}", self.week_of, self.open_total)
    }
}

fn summary(week_starting: Date, counts: &DigestCounts) -> String {
    let mut text = format!("Vectispire — week of {}: {} open", iso(week_starting), counts.open_total);
    if counts.overdue_count > 0 {
        text.push_str(&format!(", {} past their remediation deadline", counts.overdue_count));
    }
    text.push_str(&format!(
        ". {} appeared, {} resolved. {} of {} targets failing.",
        counts.opened_this_week, counts.resolved_this_week, counts.failing_targets, counts.total_targets
    ));
    // Named whenever it is not zero: an unexamined target passes every policy, and silence would read it as healthy.
    if counts.never_scanned > 0 || counts.last_scan_failed > 0 {
        text.push_str(&format!(
            " Not examined: {} never scanned, {} whose last scan failed.",
            counts.never_scanned, counts.last_scan_failed
        ));
    }
    text
}
