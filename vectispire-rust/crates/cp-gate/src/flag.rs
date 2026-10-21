//! The boolean knobs of a gate policy, each carrying the value that tightens it.

use serde::{Deserialize, Serialize};

/// The boolean knobs of a gate policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyFlag {
    /// Fail on any open issue in the CISA KEV catalog, whatever its severity.
    FailOnKev,
    /// Also count issues a human has already settled.
    IncludeTriaged,
    /// Let AI review findings weigh on the verdict.
    IncludeAiReview,
    /// Let plugin and imported findings weigh on the verdict.
    IncludePlugins,
    /// Fail only on issues that have a published fix — which evaluates fewer of them.
    FixableOnly,
    /// Refuse a verdict whose code analysis reached none of the target's ecosystems.
    FailOnUncoveredLanguages,
}

impl PolicyFlag {
    pub const ALL: [PolicyFlag; 6] = [
        PolicyFlag::FailOnKev,
        PolicyFlag::IncludeTriaged,
        PolicyFlag::IncludeAiReview,
        PolicyFlag::IncludePlugins,
        PolicyFlag::FixableOnly,
        PolicyFlag::FailOnUncoveredLanguages,
    ];

    /// The name reported back to callers. The API speaks snake_case.
    pub fn wire_name(self) -> &'static str {
        match self {
            PolicyFlag::FailOnKev => "fail_on_kev",
            PolicyFlag::IncludeTriaged => "include_triaged",
            PolicyFlag::IncludeAiReview => "include_ai_review",
            PolicyFlag::IncludePlugins => "include_plugins",
            PolicyFlag::FixableOnly => "fixable_only",
            PolicyFlag::FailOnUncoveredLanguages => "fail_on_uncovered_languages",
        }
    }

    /// The value that makes the policy stricter, and is therefore the one a caller may set.
    pub fn strict_value(self) -> bool {
        match self {
            PolicyFlag::FailOnKev => true,
            PolicyFlag::IncludeTriaged => true,
            PolicyFlag::IncludeAiReview => true,
            PolicyFlag::IncludePlugins => true,
            PolicyFlag::FixableOnly => false,
            PolicyFlag::FailOnUncoveredLanguages => true,
        }
    }

    pub fn from_wire_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|flag| flag.wire_name() == name)
    }
}
