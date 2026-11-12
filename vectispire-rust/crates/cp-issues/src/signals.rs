//! The SIEM events the backlog itself raises, as the SOC reads them — `IssueSignals`.
//!
//! **What an event says about an issue, and what it leaves out.** The issue's number, its target (`cs1`, named as
//! the KEV event names it — `repository 12`), its identifier (`cs3`: the CVE, or the secret's rule) and its package
//! (`cs4`). Never the issue's description: for a secret it is the scanner's prose, and nothing on this path should
//! come near the matched value. A SOC that needs more opens the issue.

use time::{Duration, OffsetDateTime};
use vectispire_domain::instant::Instant;
use vectispire_domain::siem::{CefEvent, InvalidEvent, SecurityEventType};
use vectispire_domain::{FindingType, Severity};

/// What an event names of an issue — the row's columns the two events read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Signalled<'a> {
    pub id: i64,
    pub identifier: &'a str,
    pub file_path: Option<&'a str>,
    pub package_name: Option<&'a str>,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub first_seen_at: OffsetDateTime,
}

/// Whether a newly created issue is a leak a SOC is told about: a secret, high or critical. Every secret the shipped
/// scanner reports is graded high; the bound is written down so that a scanner grading some lower does not page anyone
/// for them.
pub(crate) fn is_leak(type_: &str, severity: &str) -> bool {
    type_ == FindingType::Secret.wire_name() && Severity::of(Some(severity)).is_at_least(Severity::High)
}

pub(crate) fn secret_leak(issue: Signalled<'_>) -> Result<CefEvent, InvalidEvent> {
    let path = issue.file_path.map(|path| format!(" in {path}")).unwrap_or_default();
    let target = target_of(issue);
    CefEvent::builder(SecurityEventType::SecretLeakDetected, instant(issue.first_seen_at))
        .message(format!("Secret matching rule {} found{path} (issue {})", issue.identifier, issue.id).as_str())
        .target(target.as_deref())
        .identifier(issue.identifier)
        .build()
}

/// `due_at`: when the window closed — the event's time, which is when the breach happened and not when the hourly
/// turn noticed it.
pub(crate) fn sla_breach(
    issue: Signalled<'_>,
    severity: Severity,
    window: Duration,
    due_at: OffsetDateTime,
) -> Result<CefEvent, InvalidEvent> {
    let target = target_of(issue);
    let message = format!(
        "{} issue {} ({}) passed its {}-day remediation deadline, open since {}",
        severity.wire_name().to_ascii_uppercase(),
        issue.id,
        issue.identifier,
        window.whole_days(),
        vectispire_cp_audit::iso_instant(issue.first_seen_at)
    );
    CefEvent::builder(SecurityEventType::SlaBreached, instant(due_at))
        .issue_severity(severity)
        .message(message.as_str())
        .target(target.as_deref())
        .identifier(issue.identifier)
        .component(issue.package_name)
        .build()
}

fn target_of(issue: Signalled<'_>) -> Option<String> {
    match (issue.repo_id, issue.container_id) {
        (Some(repo), _) => Some(format!("repository {repo}")),
        (None, Some(container)) => Some(format!("container {container}")),
        (None, None) => None,
    }
}

fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn issue() -> Signalled<'static> {
        Signalled {
            id: 41,
            identifier: "aws-access-token",
            file_path: Some("config/prod.env"),
            package_name: None,
            repo_id: Some(12),
            container_id: None,
            first_seen_at: OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap(),
        }
    }

    #[test]
    fn a_leak_is_a_secret_graded_high_or_above() {
        assert!(is_leak("secret", "high"));
        assert!(is_leak("secret", "CRITICAL"));
        assert!(!is_leak("secret", "medium"));
        assert!(!is_leak("sca", "critical"));
    }

    #[test]
    fn a_leak_names_the_rule_the_path_and_the_issue_never_the_description() {
        let event = secret_leak(issue()).unwrap();
        assert_eq!(event.event_type(), SecurityEventType::SecretLeakDetected);
        assert_eq!(event.message(), Some("Secret matching rule aws-access-token found in config/prod.env (issue 41)"));
        assert!(event.extensions().iter().any(|(_, value)| value == "repository 12"));
        let pathless =
            secret_leak(Signalled { file_path: None, container_id: Some(3), repo_id: None, ..issue() }).unwrap();
        assert_eq!(pathless.message(), Some("Secret matching rule aws-access-token found (issue 41)"));
        assert!(pathless.extensions().iter().any(|(_, value)| value == "container 3"));
    }

    #[test]
    fn a_breach_is_dated_when_the_window_closed_and_says_the_window_in_days() {
        let due = issue().first_seen_at + Duration::days(30);
        let event = sla_breach(issue(), Severity::High, Duration::days(30), due).unwrap();
        assert_eq!(event.event_type(), SecurityEventType::SlaBreached);
        assert_eq!(event.timestamp(), instant(due));
        assert_eq!(
            event.message(),
            Some(
                "HIGH issue 41 (aws-access-token) passed its 30-day remediation deadline, open since 2026-09-21T14:13:20Z"
            )
        );
    }
}
