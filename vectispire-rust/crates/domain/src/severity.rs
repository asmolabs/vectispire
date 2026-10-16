//! `Severity`, the vocabulary every finding ranks by.

use serde::Serialize;

/// A severity, in Vectispire's vocabulary — `Severity`, declared worst first.
///
/// Shared by the dependency and source-analysis findings, as the Java enum is. On the wire it is the
/// enum's name, upper case, as the agent's Jackson mapper writes an enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Negligible,
    Unknown,
}

impl Severity {
    /// The lowercase form the API and the database use.
    pub fn wire_name(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Negligible => "negligible",
            Severity::Unknown => "unknown",
        }
    }

    /// `Severity.of`: trimmed as `String.trim` trims, lower-cased, matched against the wire names, and
    /// [`Severity::Unknown`] for anything else — lenient, because scanners invent labels and a value
    /// nobody anticipated must rank last and be evaluated, not throw.
    pub fn of(value: Option<&str>) -> Severity {
        let Some(value) = value else { return Severity::Unknown };
        let normalized = value.trim_matches(|c: char| c <= ' ').to_lowercase();
        [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Negligible, Severity::Unknown]
            .into_iter()
            .find(|severity| severity.wire_name() == normalized)
            .unwrap_or(Severity::Unknown)
    }
}
