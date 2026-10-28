//! Policy resolution and requested policy types.

use std::collections::BTreeMap;

use vectispire_domain::Severity;

use crate::flag::PolicyFlag;
use crate::gate::{Hardened, PolicyGate};
use crate::policy::GatePolicy;

/// What a caller said about the severity threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeverityRequest {
    /// The caller did not mention it.
    #[default]
    Unset,
    /// The caller asked for no severity rule at all.
    Disabled,
    /// The caller asked for this threshold.
    Threshold(Severity),
}

/// What a caller actually sent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestedPolicy {
    pub fail_on_severity: SeverityRequest,
    pub flags: BTreeMap<PolicyFlag, bool>,
}

impl RequestedPolicy {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn with_flag(&self, flag: PolicyFlag, value: bool) -> Self {
        let mut updated = self.clone();
        updated.flags.insert(flag, value);
        updated
    }

    pub fn with_severity(&self, severity: SeverityRequest) -> Self {
        let mut updated = self.clone();
        updated.fail_on_severity = severity;
        updated
    }
}

/// Where a policy came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    Target,
    Global,
    BuiltIn,
}

impl PolicySource {
    pub fn name(self) -> &'static str {
        match self {
            PolicySource::Target => "TARGET",
            PolicySource::Global => "GLOBAL",
            PolicySource::BuiltIn => "BUILT_IN",
        }
    }

    pub fn wire_name(self) -> &'static str {
        match self {
            PolicySource::Target => "target",
            PolicySource::Global => "global",
            PolicySource::BuiltIn => "built-in",
        }
    }

    pub fn scope_label(self) -> Option<&'static str> {
        match self {
            PolicySource::Target => Some("the target's"),
            PolicySource::Global => Some("the global"),
            PolicySource::BuiltIn => None,
        }
    }
}

/// A stored policy and the version it was saved under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPolicy {
    pub policy: GatePolicy,
    pub version: i32,
}

/// A resolved policy after weighing against requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub policy: GatePolicy,
    pub source: PolicySource,
    pub version: Option<i32>,
    pub ignored_relaxations: Vec<String>,
}

impl ResolvedPolicy {
    pub fn describe_source(&self) -> String {
        match self.source {
            PolicySource::BuiltIn => "the application's default policy".to_owned(),
            PolicySource::Target | PolicySource::Global => {
                let label = self.source.scope_label().unwrap_or("the");
                let v = self.version.map(|ver| ver.to_string()).unwrap_or_else(|| "?".to_owned());
                format!("{label} policy v{v}")
            }
        }
    }
}

/// What is on file, before a request is weighed against it.
#[derive(Debug, Clone, Default)]
pub struct PolicyLookup {
    pub for_target: Option<StoredPolicy>,
    pub global: Option<StoredPolicy>,
}

/// Which policies a resolution is allowed to consider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyScopeChoice {
    Target,
    Global,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyResolution;

impl PolicyResolution {
    pub fn resolve(lookup: PolicyLookup, requested: &RequestedPolicy, scope: PolicyScopeChoice) -> ResolvedPolicy {
        let mut stored = None;
        let mut source = PolicySource::Global;

        if scope == PolicyScopeChoice::Target && lookup.for_target.is_some() {
            stored = lookup.for_target;
            source = PolicySource::Target;
        } else if lookup.global.is_some() {
            stored = lookup.global;
        }

        let base = stored.as_ref().map(|s| s.policy.clone()).unwrap_or(GatePolicy::BUILT_IN);
        let version = stored.as_ref().map(|s| s.version);
        if stored.is_none() {
            source = PolicySource::BuiltIn;
        }

        let Hardened { policy, ignored_relaxations } = PolicyGate::harden(base, requested);
        ResolvedPolicy { policy, source, version, ignored_relaxations }
    }
}
