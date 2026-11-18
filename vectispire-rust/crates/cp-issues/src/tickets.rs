//! What `tickets` asks of the issues: whether a reference is the configured tracker's ([`TicketReferences`], Java's
//! port of the same name), and an issue as a ticket's title and body read it ([`TicketableIssue`], Java's
//! `Tickets.TicketableIssue` built by `IssueViews.forTicket`).

use vectispire_cp_http::credentials::BoxFuture;
use vectispire_domain::dependency_graph::Directness;
use vectispire_domain::integrations::Integration;
use vectispire_domain::{FindingType, Severity};

use crate::views::IssueView;

/// Whether a ticket reference is one the configured tracker issues.
///
/// **Declared here, implemented by `tickets`.** Attaching a ticket is an issue's decision, but what a valid reference
/// looks like is the tracker's knowledge, and `tickets` already depends on `issues` — its webhook and its sweep
/// transition issues. Calling the tracker's service from here would close a cycle between the two modules; the port
/// turns the edge around (decision 0026), and `cp-app` hands the implementation in.
pub trait TicketReferences: Send + Sync {
    /// `reference` is trimmed, non-empty and within the column's length. `Ok(None)` when it is acceptable; otherwise
    /// the sentence the person who typed it is answered with (400).
    ///
    /// [`TicketReferenceError::IntegrationDisabled`] while the configured tracker's integration is switched off
    /// (decision 0040 §3): 409, not a 400 about the reference — the same reference is accepted once it is back on.
    fn refusal<'a>(&'a self, reference: &'a str) -> BoxFuture<'a, Result<Option<String>, TicketReferenceError>>;
}

/// Why a reference could not be judged.
#[derive(Debug, thiserror::Error)]
pub enum TicketReferenceError {
    /// `IntegrationDisabledException`: the configured tracker is suspended — 409 `integration-disabled`, naming it.
    #[error("{}", .0.disabled_message(""))]
    IntegrationDisabled(Integration),
    /// The tracker's standing could not be read (the settings' database): a failure, never an acceptance.
    #[error("{0}")]
    Failed(String),
}

/// No tracker configured: every reference is a label, accepted, and nothing is ever sent — what Java's
/// `TrackerTicketReferences` answers for `TicketProvider.NONE`. The stand-in until `cp-app` hands `tickets`' in.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTracker;

impl TicketReferences for NoTracker {
    fn refusal<'a>(&'a self, _reference: &'a str) -> BoxFuture<'a, Result<Option<String>, TicketReferenceError>> {
        Box::pin(async { Ok(None) })
    }
}

/// `ExportableIssue.FixState`: what the scanner said of a fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixState {
    Fixed,
    NotFixed,
    WontFix,
    Unknown,
}

impl FixState {
    pub fn wire_name(self) -> &'static str {
        match self {
            FixState::Fixed => "fixed",
            FixState::NotFixed => "not-fixed",
            FixState::WontFix => "wont-fix",
            FixState::Unknown => "unknown",
        }
    }

    /// `fromWireName(...).orElse(UNKNOWN)`. **Never [`FixState::Fixed`] for a value nobody recognises**: "a fix exists"
    /// is the claim that closes a ticket, and it must come from a value the scanner actually wrote.
    pub fn of(value: Option<&str>) -> FixState {
        match value {
            Some("fixed") => FixState::Fixed,
            Some("not-fixed") => FixState::NotFixed,
            Some("wont-fix") => FixState::WontFix,
            _ => FixState::Unknown,
        }
    }
}

/// `Tickets.TicketableIssue`: what a ticket's title and body read, and nothing more.
#[derive(Debug, Clone, PartialEq)]
pub struct TicketableIssue {
    pub id: i64,
    /// `None` for a type this version does not know — never guessed.
    pub type_: Option<FindingType>,
    pub identifier: String,
    pub severity: Severity,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub fix_versions: Option<String>,
    pub fix_state: FixState,
    pub directness: Directness,
    pub file_path: Option<String>,
    pub line: Option<i32>,
    pub kev: bool,
    pub epss_score: Option<f64>,
    pub link: Option<String>,
    pub description: Option<String>,
    pub fingerprint: String,
}

impl IssueView {
    /// `IssueViews.forTicket`: the one mapping, so that the sweep and any other reader cannot disagree about a row.
    pub fn for_ticket(&self) -> TicketableIssue {
        TicketableIssue {
            id: self.id,
            type_: FindingType::from_wire_name(Some(&self.type_)),
            identifier: self.identifier.clone(),
            // `Severity.of`: lenient, an unreadable value is `UNKNOWN`.
            severity: Severity::of(Some(&self.severity)),
            package_name: self.package_name.clone(),
            package_version: self.package_version.clone(),
            fix_versions: self.fix_versions.clone(),
            fix_state: FixState::of(self.fix_state.as_deref()),
            // Null is unknown and stays unknown: a container scan cannot tell direct from transitive, and reading
            // the absence as "transitive" would put a confident wrong answer in a ticket somebody acts on.
            directness: self.is_direct_dependency.map_or(Directness::Unknown, Directness::of),
            file_path: self.file_path.clone(),
            line: self.line,
            kev: self.is_kev,
            epss_score: self.epss_score,
            link: self.link.clone(),
            description: self.description.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_fix_state_is_unknown_never_fixed() {
        assert_eq!(FixState::of(Some("fixed")), FixState::Fixed);
        assert_eq!(FixState::of(Some("not-fixed")), FixState::NotFixed);
        assert_eq!(FixState::of(Some("wont-fix")), FixState::WontFix);
        assert_eq!(FixState::of(Some("FIXED")), FixState::Unknown);
        assert_eq!(FixState::of(None), FixState::Unknown);
        for state in [FixState::Fixed, FixState::NotFixed, FixState::WontFix, FixState::Unknown] {
            assert_eq!(FixState::of(Some(state.wire_name())), state);
        }
    }
}
