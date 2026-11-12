//! `TriageStatus`: where an issue stands with the humans — `common.domain.issues.TriageStatus`.
//!
//! Here rather than in `cp-issues` because the SIEM's [`crate::siem::triage_signals`] asks it too, as the Java
//! class sits in `vectispire-common` for the same reason: two copies could disagree on [`TriageStatus::is_settled`],
//! and that disagreement would decide both what fails a build and what a SOC hears about.

use crate::java;

/// A triage status, in the Java enum's declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TriageStatus {
    UnderReview,
    Affected,
    PendingApproval,
    NotAffected,
    WillNotFix,
    Fixed,
}

impl TriageStatus {
    pub const ALL: [TriageStatus; 6] = [
        TriageStatus::UnderReview,
        TriageStatus::Affected,
        TriageStatus::PendingApproval,
        TriageStatus::NotAffected,
        TriageStatus::WillNotFix,
        TriageStatus::Fixed,
    ];

    /// Whether a human decision has taken this issue out of the way. A new status has to declare whether it
    /// settles anything — the gate and the SOC's signals ask this, never a list.
    pub fn is_settled(&self) -> bool {
        matches!(self, TriageStatus::NotAffected | TriageStatus::WillNotFix | TriageStatus::Fixed)
    }

    pub fn wire_name(&self) -> &'static str {
        match self {
            TriageStatus::UnderReview => "under_review",
            TriageStatus::Affected => "affected",
            TriageStatus::PendingApproval => "pending_approval",
            TriageStatus::NotAffected => "not_affected",
            TriageStatus::WillNotFix => "will_not_fix",
            TriageStatus::Fixed => "fixed",
        }
    }

    /// `fromWireName`: `String.trim`, then `toLowerCase(Locale.ROOT)`, then an exact match — Java's spelling of
    /// both, so a value with a leading control character or a trailing no-break space is read as Java reads it.
    pub fn from_wire_name(value: &str) -> Option<Self> {
        let normalized = java::to_lower_root(java::trim(value));
        TriageStatus::ALL.into_iter().find(|status| status.wire_name() == normalized)
    }

    /// The settled statuses by wire name, derived from [`TriageStatus::is_settled`] so the two cannot disagree.
    pub fn settled_wire_names() -> &'static [&'static str] {
        &["not_affected", "will_not_fix", "fixed"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settled_names_are_the_settled_statuses() {
        let derived: Vec<&str> =
            TriageStatus::ALL.iter().filter(|status| status.is_settled()).map(|status| status.wire_name()).collect();
        assert_eq!(derived, TriageStatus::settled_wire_names());
    }

    #[test]
    fn a_wire_name_is_trimmed_and_lowered_as_java_does() {
        assert_eq!(TriageStatus::from_wire_name(" FIXED "), Some(TriageStatus::Fixed));
        // `String.trim` strips every char up to U+0020, the controls included, and nothing beyond it.
        assert_eq!(TriageStatus::from_wire_name("\u{1}fixed"), Some(TriageStatus::Fixed));
        assert_eq!(TriageStatus::from_wire_name("\u{a0}fixed"), None);
        assert_eq!(TriageStatus::from_wire_name("a_status_from_the_future"), None);
    }
}
