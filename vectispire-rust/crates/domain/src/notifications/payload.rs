//! `NotificationPayload`: what a scan changed, formatted for a webhook — the generic channel's body, and what the
//! other four render from.
//!
//! **A snapshot**: it says what the scan found, not what the issues look like once somebody triaged half of them.
//! Stored in the outbox and read back by the channel at delivery, so its members are a data contract: Java's names, in
//! Java's order (`@JsonPropertyOrder`), the payload's absent strings left out (`NON_NULL`) and a detail's written as
//! `null` (`ALWAYS`).

use serde::{Deserialize, Serialize};

use crate::finding_type::FindingType;
use crate::severity::Severity;

/// How many issues are named in the body; the rest are counted. A webhook body with four hundred entries is a denial
/// of service against its reader, and the API exists for the full list.
pub const MAX_DETAILED_ISSUES: usize = 10;

/// The payload. Read back leniently, as Java's relay maps it: an unknown member is ignored, a missing number is 0.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub scan_id: i64,
    #[serde(default)]
    pub new_count: i32,
    #[serde(default)]
    pub reopened_count: i32,
    #[serde(default)]
    pub resolved_count: i32,
    #[serde(default)]
    pub kev_count: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<String>,
    #[serde(default)]
    pub issues: Vec<Detail>,
    #[serde(default)]
    pub truncated: i32,
    /// Null until the outbox stamps it: what a receiver deduplicates on, delivery being at least once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

/// One named issue. Every member written, `null` included.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detail {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub identifier: Option<String>,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub is_kev: bool,
    #[serde(default)]
    pub epss_score: Option<f64>,
    #[serde(default, rename = "package")]
    pub package_name: Option<String>,
    #[serde(default)]
    pub file_path: Option<String>,
    /// The most useful field for whoever reads the alert.
    #[serde(default)]
    pub fix_versions: Option<String>,
    #[serde(default)]
    pub link: Option<String>,
}

/// An issue's contribution to the message. Deliberately narrower than the issue.
#[derive(Debug, Clone, PartialEq)]
pub struct NotifiableIssue {
    pub id: i64,
    pub identifier: Option<String>,
    pub kind: Option<FindingType>,
    pub severity: Option<Severity>,
    pub kev: bool,
    pub epss_score: Option<f64>,
    pub package_name: Option<String>,
    pub file_path: Option<String>,
    pub fix_versions: Option<String>,
    pub link: Option<String>,
}

impl NotifiableIssue {
    fn to_detail(&self) -> Detail {
        Detail {
            id: self.id,
            identifier: self.identifier.clone(),
            kind: self.kind.map(|kind| kind.wire_name().to_owned()),
            severity: self.severity.map(|severity| severity.wire_name().to_owned()),
            is_kev: self.kev,
            epss_score: self.epss_score,
            package_name: self.package_name.clone(),
            file_path: self.file_path.clone(),
            fix_versions: self.fix_versions.clone(),
            link: self.link.clone(),
        }
    }
}

/// `NotificationPayload.Delta`.
#[derive(Debug, Clone, PartialEq)]
pub struct Delta {
    pub target_name: String,
    pub scan_id: i64,
    pub new_issues: Vec<NotifiableIssue>,
    pub reopened_issues: Vec<NotifiableIssue>,
    pub resolved_count: i32,
    pub min_severity: Severity,
}

impl NotificationPayload {
    /// `NotificationPayload.of`.
    pub fn of(delta: &Delta) -> NotificationPayload {
        let all: Vec<&NotifiableIssue> = delta.new_issues.iter().chain(&delta.reopened_issues).collect();
        let kev_count = all.iter().filter(|issue| issue.kev).count();

        let mut parts = Vec::new();
        if !delta.new_issues.is_empty() {
            parts.push(format!("{} new issue(s)", delta.new_issues.len()));
        }
        if !delta.reopened_issues.is_empty() {
            parts.push(format!("{} reappeared", delta.reopened_issues.len()));
        }
        if kev_count > 0 {
            parts.push(format!("{kev_count} actively exploited"));
        }
        let mut text = format!("Vectispire — {}: {}", delta.target_name, parts.join(", "));
        if delta.resolved_count > 0 {
            text.push_str(&format!(" ({} resolved)", delta.resolved_count));
        }

        NotificationPayload {
            text: Some(text),
            target: Some(delta.target_name.clone()),
            scan_id: delta.scan_id,
            new_count: count(delta.new_issues.len()),
            reopened_count: count(delta.reopened_issues.len()),
            resolved_count: delta.resolved_count,
            kev_count: i64::try_from(kev_count).unwrap_or(i64::MAX),
            min_severity: Some(delta.min_severity.wire_name().to_owned()),
            issues: all.iter().take(MAX_DETAILED_ISSUES).map(|issue| issue.to_detail()).collect(),
            truncated: count(all.len().saturating_sub(MAX_DETAILED_ISSUES)),
            message_id: None,
        }
    }

    /// The JSON as stored and as posted.
    pub fn to_json(&self) -> String {
        crate::wire::to_wire_string(self)
    }
}

fn count(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn issue(id: i64, kev: bool) -> NotifiableIssue {
        NotifiableIssue {
            id,
            identifier: Some(format!("CVE-{id}")),
            kind: Some(FindingType::Vulnerability),
            severity: Some(Severity::High),
            kev,
            epss_score: None,
            package_name: None,
            file_path: None,
            fix_versions: None,
            link: None,
        }
    }

    #[test]
    fn the_text_counts_and_the_list_is_cut_at_ten() {
        let delta = Delta {
            target_name: "web".into(),
            scan_id: 7,
            new_issues: (1..=11).map(|id| issue(id, id == 1)).collect(),
            reopened_issues: vec![issue(20, false)],
            resolved_count: 3,
            min_severity: Severity::High,
        };
        let payload = NotificationPayload::of(&delta);
        assert_eq!(
            payload.text.as_deref(),
            Some("Vectispire — web: 11 new issue(s), 1 reappeared, 1 actively exploited (3 resolved)")
        );
        assert_eq!((payload.issues.len(), payload.truncated, payload.kev_count), (10, 2, 1));
        let json = payload.to_json();
        assert!(json.starts_with(r#"{"text":"#), "{json}");
        assert!(!json.contains("message_id"), "{json}");
        assert!(
            json.contains(r#""type":"vulnerability","severity":"high","is_kev":true,"epss_score":null,"package":null"#)
        );
        let back: NotificationPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back, payload);
    }
}
