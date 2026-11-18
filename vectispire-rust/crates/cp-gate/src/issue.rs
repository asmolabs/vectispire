//! The slice of an issue a verdict looks at.

use vectispire_cp_issues::triage::TriageStatus;
use vectispire_domain::{FindingType, Severity, java};

/// The slice of an issue a verdict looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateIssue {
    pub id: i64,
    pub open: bool,
    pub type_: Option<FindingType>,
    pub severity: Severity,
    pub identifier: String,
    pub package_name: Option<String>,
    pub fix_versions: Option<String>,
    pub kev: bool,
    pub triage: Option<TriageStatus>,
}

impl GateIssue {
    /// `IssueViews.forGate`: the one mapping, shared with `tickets`' sweep, so that a ticket is opened for exactly
    /// what the gate would fail on.
    pub fn of_view(v: &vectispire_cp_issues::IssueView) -> GateIssue {
        GateIssue {
            id: v.id,
            open: v.state == "open",
            type_: FindingType::from_wire_name(Some(&v.type_)),
            severity: Severity::of(Some(&v.severity)),
            identifier: v.identifier.clone(),
            package_name: v.package_name.clone(),
            fix_versions: v.fix_versions.clone(),
            kev: v.is_kev,
            triage: TriageStatus::from_wire_name(&v.triage_status),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: i64,
        open: bool,
        type_: Option<FindingType>,
        severity: Option<Severity>,
        identifier: impl Into<String>,
        package_name: Option<String>,
        fix_versions: Option<String>,
        kev: bool,
        triage: Option<TriageStatus>,
    ) -> Self {
        Self {
            id,
            open,
            type_,
            severity: severity.unwrap_or(Severity::Unknown),
            identifier: identifier.into(),
            package_name,
            fix_versions,
            kev,
            triage,
        }
    }

    pub fn has_published_fix(&self) -> bool {
        // `isBlank`: a scanner writing "" or spaces for "no fix" has not published one — in Java's whitespace.
        self.fix_versions.as_deref().is_some_and(|versions| !java::is_blank(versions))
    }
}
