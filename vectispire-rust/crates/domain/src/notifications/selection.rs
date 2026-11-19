//! `NotificationSelection`: which of the new or reappeared issues deserve a message — only on change, and only above
//! a threshold. One notification per scan teaches people to filter the channel.

use super::payload::NotifiableIssue;
use crate::finding_type::FindingType;
use crate::severity::Severity;

pub const DEFAULT_MIN_SEVERITY: Severity = Severity::High;

/// `always_on_kev` lets an actively exploited vulnerability through **whatever its severity**: a threshold alone
/// discards a "medium" being exploited today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub min_severity: Severity,
    pub always_on_kev: bool,
}

/// **Quality findings never qualify**, whatever their severity: Semgrep maps `ERROR` to `high`, and the first scan
/// with SAST on would announce several hundred issues. An issue with no severity ranks lowest.
pub fn notable(issues: &[NotifiableIssue], options: Options) -> Vec<NotifiableIssue> {
    issues
        .iter()
        .filter(|issue| issue.kind != Some(FindingType::Quality))
        .filter(|issue| {
            (options.always_on_kev && issue.kev)
                || issue.severity.unwrap_or(Severity::Unknown).is_at_least(options.min_severity)
        })
        .cloned()
        .collect()
}
