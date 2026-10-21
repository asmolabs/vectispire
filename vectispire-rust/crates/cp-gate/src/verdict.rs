//! GateVerdict: pass/fail verdict and violations.

use std::collections::BTreeMap;

use vectispire_domain::Severity;

/// Which rule was tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    Kev,
    Severity,
    /// No rule reached the target's ecosystems, so nothing was examined.
    Coverage,
    /// No scan of the target ran to its end.
    Observation,
}

impl Rule {
    pub fn wire_name(self) -> &'static str {
        match self {
            Rule::Kev => "kev",
            Rule::Severity => "severity",
            Rule::Coverage => "coverage",
            Rule::Observation => "observation",
        }
    }
}

/// A violation of a gate rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub rule: Rule,
    pub issue_id: Option<i64>,
    pub identifier: Option<String>,
    pub severity: Option<Severity>,
    pub package_name: Option<String>,
    pub fix_versions: Option<String>,
    pub reason: String,
}

/// What code analysis could reach on this target.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Coverage {
    pub uncovered_ecosystems: Vec<String>,
}

impl Coverage {
    pub const NOT_APPLICABLE: Coverage = Coverage { uncovered_ecosystems: Vec::new() };

    pub fn new(uncovered: Vec<String>) -> Self {
        Self { uncovered_ecosystems: uncovered }
    }
}

/// The answer a pipeline gets: whether to fail, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateVerdict {
    pub passed: bool,
    pub violations: Vec<Violation>,
    pub evaluated: i32,
    pub counts_by_severity: BTreeMap<Severity, i64>,
}
