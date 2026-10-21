//! What a caller sent about a gate policy, every field boxed — and the one reading of it.

use vectispire_domain::Severity;

use crate::error::GateError;
use crate::flag::PolicyFlag;
use crate::policy::GatePolicy;
use crate::resolution::{RequestedPolicy, SeverityRequest};

/// What a caller sent about a gate policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GatePolicyFields {
    pub fail_on_severity: Option<String>,
    pub fail_on_kev: Option<bool>,
    pub fixable_only: Option<bool>,
    pub include_triaged: Option<bool>,
    pub include_ai_review: Option<bool>,
    pub fail_on_uncovered_languages: Option<bool>,
    pub include_plugins: Option<bool>,
}

impl GatePolicyFields {
    pub fn new(
        fail_on_severity: Option<String>,
        fail_on_kev: Option<bool>,
        fixable_only: Option<bool>,
        include_triaged: Option<bool>,
        include_ai_review: Option<bool>,
        fail_on_uncovered_languages: Option<bool>,
        include_plugins: Option<bool>,
    ) -> Self {
        Self {
            fail_on_severity,
            fail_on_kev,
            fixable_only,
            include_triaged,
            include_ai_review,
            fail_on_uncovered_languages,
            include_plugins,
        }
    }

    /// Read as one verdict's request: an absent field was not mentioned.
    pub fn as_request(&self) -> Result<RequestedPolicy, GateError> {
        let mut requested = RequestedPolicy::none();
        if let Some(severity_str) = &self.fail_on_severity {
            requested = requested.with_severity(Self::severity(severity_str)?);
        }
        if let Some(v) = self.fail_on_kev {
            requested = requested.with_flag(PolicyFlag::FailOnKev, v);
        }
        if let Some(v) = self.fixable_only {
            requested = requested.with_flag(PolicyFlag::FixableOnly, v);
        }
        if let Some(v) = self.include_triaged {
            requested = requested.with_flag(PolicyFlag::IncludeTriaged, v);
        }
        if let Some(v) = self.include_ai_review {
            requested = requested.with_flag(PolicyFlag::IncludeAiReview, v);
        }
        if let Some(v) = self.fail_on_uncovered_languages {
            requested = requested.with_flag(PolicyFlag::FailOnUncoveredLanguages, v);
        }
        if let Some(v) = self.include_plugins {
            requested = requested.with_flag(PolicyFlag::IncludePlugins, v);
        }
        Ok(requested)
    }

    /// Read as a stored policy replacing the previous one: every field is read, none is defaulted
    /// from what is already stored (except the two newest flags).
    pub fn as_replacement(&self) -> Result<GatePolicy, GateError> {
        let fail_on_severity = match &self.fail_on_severity {
            Some(s) if !s.trim().is_empty() => s,
            _ => {
                return Err(GateError::InvalidInput(
                    "\"fail_on_severity\" is required — a severity, or \"none\" to switch the rule off.".to_owned(),
                ));
            }
        };

        let severity_thresh = match Self::severity(fail_on_severity)? {
            SeverityRequest::Threshold(t) => Some(t),
            SeverityRequest::Disabled => None,
            SeverityRequest::Unset => None,
        };

        Ok(GatePolicy {
            fail_on_severity: severity_thresh,
            fail_on_kev: Self::required(self.fail_on_kev, "fail_on_kev")?,
            fixable_only: Self::required(self.fixable_only, "fixable_only")?,
            include_triaged: Self::required(self.include_triaged, "include_triaged")?,
            include_ai_review: Self::required(self.include_ai_review, "include_ai_review")?,
            fail_on_uncovered_languages: self.fail_on_uncovered_languages.unwrap_or(false),
            include_plugins: self.include_plugins.unwrap_or(false),
        })
    }

    /// "none" switches the severity rule off; anything else is a threshold.
    fn severity(value: &str) -> Result<SeverityRequest, GateError> {
        let trimmed = value.trim();
        if trimmed.eq_ignore_ascii_case("none") {
            return Ok(SeverityRequest::Disabled);
        }
        let sev = Severity::of(Some(trimmed));
        if sev == Severity::Unknown {
            return Err(GateError::InvalidInput(format!("Unknown severity: \"{value}\".")));
        }
        Ok(SeverityRequest::Threshold(sev))
    }

    fn required<T>(value: Option<T>, field: &str) -> Result<T, GateError> {
        value.ok_or_else(|| GateError::InvalidInput(format!("\"{field}\" is required.")))
    }
}
