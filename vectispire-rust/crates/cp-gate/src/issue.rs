//! The slice of an issue a verdict looks at.

use vectispire_cp_issues::triage::TriageStatus;
use vectispire_domain::{FindingType, Severity};

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
        match &self.fix_versions {
            Some(v) => !v.trim().is_empty(),
            None => false,
        }
    }
}
