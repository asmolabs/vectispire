//! What a caller considers unacceptable.

use vectispire_domain::Severity;

use crate::flag::PolicyFlag;

/// What a caller considers unacceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatePolicy {
    /// Fail as soon as an open issue reaches this severity; `None` disables the severity rule entirely.
    pub fail_on_severity: Option<Severity>,
    pub fail_on_kev: bool,
    pub fixable_only: bool,
    pub include_triaged: bool,
    pub include_ai_review: bool,
    pub fail_on_uncovered_languages: bool,
    pub include_plugins: bool,
}

impl GatePolicy {
    /// The default: High severity, KEV fails, fixable only is off, triaged excluded, AI excluded,
    /// uncovered languages off, plugins excluded.
    pub const BUILT_IN: GatePolicy = GatePolicy {
        fail_on_severity: Some(Severity::High),
        fail_on_kev: true,
        fixable_only: false,
        include_triaged: false,
        include_ai_review: false,
        fail_on_uncovered_languages: false,
        include_plugins: false,
    };

    pub fn flag(&self, flag: PolicyFlag) -> bool {
        match flag {
            PolicyFlag::FailOnKev => self.fail_on_kev,
            PolicyFlag::IncludeTriaged => self.include_triaged,
            PolicyFlag::IncludeAiReview => self.include_ai_review,
            PolicyFlag::FixableOnly => self.fixable_only,
            PolicyFlag::FailOnUncoveredLanguages => self.fail_on_uncovered_languages,
            PolicyFlag::IncludePlugins => self.include_plugins,
        }
    }

    pub fn with_flag(&self, flag: PolicyFlag, value: bool) -> Self {
        let mut updated = self.clone();
        match flag {
            PolicyFlag::FailOnKev => updated.fail_on_kev = value,
            PolicyFlag::IncludeTriaged => updated.include_triaged = value,
            PolicyFlag::IncludeAiReview => updated.include_ai_review = value,
            PolicyFlag::FixableOnly => updated.fixable_only = value,
            PolicyFlag::FailOnUncoveredLanguages => updated.fail_on_uncovered_languages = value,
            PolicyFlag::IncludePlugins => updated.include_plugins = value,
        }
        updated
    }

    pub fn with_fail_on_severity(&self, severity: Option<Severity>) -> Self {
        let mut updated = self.clone();
        updated.fail_on_severity = severity;
        updated
    }
}
