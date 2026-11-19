//! `MailMessage`: a scan's delta as an e-mail — plain text, which has no escaping to get wrong and survives being
//! quoted into a ticket; the subject carries the verdict, since a mailbox shows nothing else until it is opened.

use super::payload::{Detail, NotificationPayload};
use super::public_base;

/// `MailMessage.Content`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailContent {
    pub subject: String,
    pub body: String,
}

/// `MailMessage.of`.
pub fn of(payload: &NotificationPayload, public_url: Option<&str>) -> MailContent {
    MailContent { subject: subject_of(payload), body: body_of(payload, public_url) }
}

fn null(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("null")
}

fn subject_of(payload: &NotificationPayload) -> String {
    let mut counts = Vec::new();
    if payload.new_count > 0 {
        counts.push(format!("{} new", payload.new_count));
    }
    if payload.reopened_count > 0 {
        counts.push(format!("{} reopened", payload.reopened_count));
    }
    // The exploited count leads: the only figure here that changes what somebody does this afternoon.
    let lead = if payload.kev_count > 0 { "[exploited] " } else { "" };
    let what = if counts.is_empty() { "scan reported".to_owned() } else { counts.join(", ") };
    format!("{lead}Vectispire · {} · {what}", null(&payload.target))
}

fn body_of(payload: &NotificationPayload, public_url: Option<&str>) -> String {
    let mut lines = vec![
        null(&payload.text).to_owned(),
        String::new(),
        format!("Target:    {}", null(&payload.target)),
        format!("Scan:      #{}", payload.scan_id),
        format!("New:       {}", payload.new_count),
        format!("Reopened:  {}", payload.reopened_count),
        format!("Resolved:  {}", payload.resolved_count),
    ];
    if payload.kev_count > 0 {
        lines.push(format!("Actively exploited: {}", payload.kev_count));
    }
    lines.push(format!("Threshold: {}", null(&payload.min_severity)));

    if !payload.issues.is_empty() {
        lines.push(String::new());
        lines.push("Findings".into());
        lines.push("--------".into());
        lines.extend(payload.issues.iter().map(line));
        if payload.truncated > 0 {
            lines.push(format!("… and {} more, not listed here.", payload.truncated));
        }
    }
    if let Some(base) = public_base(public_url) {
        lines.push(String::new());
        lines.push(format!("{base}/issues"));
    }
    lines.push(String::new());
    // What a receiver deduplicates on: the same message can arrive twice.
    lines.push(format!("Message {}", null(&payload.message_id)));
    lines.join("\n")
}

fn line(issue: &Detail) -> String {
    let present = |value: &Option<String>| value.clone().filter(|value| !crate::java::is_blank(value));
    let mut line = String::from("  ");
    if issue.is_kev {
        line.push_str("[exploited] ");
    }
    line.push_str(&crate::java::to_upper_root(issue.severity.as_deref().unwrap_or("unknown")));
    line.push_str("  ");
    line.push_str(issue.identifier.as_deref().or(issue.kind.as_deref()).unwrap_or("null"));
    if let Some(name) = present(&issue.package_name) {
        line.push_str(&format!("  {name}"));
    }
    if let Some(path) = present(&issue.file_path) {
        line.push_str(&format!("  {path}"));
    }
    if let Some(fix) = present(&issue.fix_versions) {
        line.push_str(&format!("  (fixed in {fix})"));
    }
    line
}
