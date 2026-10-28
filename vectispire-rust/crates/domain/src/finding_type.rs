//! `FindingType`: the finding types, and what each one is allowed to do to a build.
//!
//! **The wire name is fingerprint material.** It is the second field of every issue's identity
//! (`fingerprint::of`), so it is spelled here exactly as the Java enum spells it, and held to
//! `reference/fingerprints/` with the rest of the fingerprint.

use serde::Serialize;

/// A finding type — `FindingType`, in Java's declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    Vulnerability,
    Secret,
    Iac,
    License,
    Eol,
    Sast,
    AiReview,
    /// Found by a plugin Vectispire ran, in the built-in worker or on an agent.
    Plugin,
    /// Declared by an internal tool's SARIF report, uploaded through a declared source.
    Imported,
    Quality,
}

/// Whether findings of a type may fail a build, and under what condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateParticipation {
    Always,
    OnRequest,
    Never,
}

impl FindingType {
    /// Every type, in Java's `values()` order — the order `fromWireName` searches.
    pub const ALL: [FindingType; 10] = [
        FindingType::Vulnerability,
        FindingType::Secret,
        FindingType::Iac,
        FindingType::License,
        FindingType::Eol,
        FindingType::Sast,
        FindingType::AiReview,
        FindingType::Plugin,
        FindingType::Imported,
        FindingType::Quality,
    ];

    /// The form stored in the database, sent over the API, and hashed into the fingerprint. Held apart
    /// from the variant's name so that renaming one is a refactor, not a data migration.
    pub fn wire_name(self) -> &'static str {
        match self {
            FindingType::Vulnerability => "vulnerability",
            FindingType::Secret => "secret",
            FindingType::Iac => "iac",
            FindingType::License => "license",
            FindingType::Eol => "eol",
            FindingType::Sast => "sast",
            FindingType::AiReview => "ai_review",
            FindingType::Plugin => "plugin",
            FindingType::Imported => "imported",
            FindingType::Quality => "quality",
        }
    }

    /// Quality never fails a build and has no flag to change that; AI review, plugins and imports
    /// count only when a policy asks (a hostile repository can steer a model, a plugin is third-party
    /// code, an import is another tool's word — decision 0017); everything else always counts.
    pub fn gate_participation(self) -> GateParticipation {
        match self {
            FindingType::AiReview | FindingType::Plugin | FindingType::Imported => GateParticipation::OnRequest,
            FindingType::Quality => GateParticipation::Never,
            _ => GateParticipation::Always,
        }
    }

    /// Whether an issue of this type belongs to one tool among several. **It decides what a clean run
    /// resolves**: one plugin reporting nothing resolves its own issues, not every other plugin's and
    /// import's on the target — so a tool-scoped type is fingerprinted with its tool key in the
    /// package's place (`fingerprint::of_tool`) and never resolved by type.
    pub fn tool_scoped(self) -> bool {
        matches!(self, FindingType::Plugin | FindingType::Imported)
    }

    /// Whether the type counts towards a security posture: only the ones that always gate, so the
    /// counters at the top of a screen mean the same thing whatever a policy lets fail a build.
    pub fn is_security(self) -> bool {
        self.gate_participation() == GateParticipation::Always
    }

    /// `FindingType.fromWireName`: an exact match — no trimming, no case folding — or nothing.
    pub fn from_wire_name(value: Option<&str>) -> Option<FindingType> {
        let value = value?;
        FindingType::ALL.into_iter().find(|kind| kind.wire_name() == value)
    }
}
