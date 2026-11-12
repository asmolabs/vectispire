//! Pass/fail verdict of a target's backlog against a policy.

use std::collections::BTreeMap;

use vectispire_domain::finding_type::GateParticipation;
use vectispire_domain::{FindingType, Severity};

use crate::flag::PolicyFlag;
use crate::issue::GateIssue;
use crate::observation::Observation;
use crate::policy::GatePolicy;
use crate::resolution::{RequestedPolicy, SeverityRequest};
use crate::verdict::{Coverage, GateVerdict, Rule, Violation};

/// Hardened policy and ignored relaxations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardened {
    pub policy: GatePolicy,
    pub ignored_relaxations: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyGate;

impl PolicyGate {
    /// Applies `policy` to a target's backlog, knowing what the examination could reach and
    /// whether there was one.
    pub fn evaluate(
        issues: &[GateIssue],
        policy: &GatePolicy,
        coverage: &Coverage,
        examination: Option<Observation>,
    ) -> GateVerdict {
        let considered: Vec<&GateIssue> = issues.iter().filter(|issue| Self::is_considered(issue, policy)).collect();

        let mut counts_by_severity: BTreeMap<Severity, i64> = BTreeMap::new();
        for issue in &considered {
            let count = counts_by_severity.entry(issue.severity).or_insert(0);
            *count = count.saturating_add(1);
        }

        let mut violations = Vec::new();

        // First, because it explains the rest: a screen showing one reason shows this one.
        if let Some(refusal) = examination.and_then(|e| e.refusal()) {
            violations.push(Violation {
                rule: Rule::Observation,
                issue_id: None,
                identifier: None,
                severity: None,
                package_name: None,
                fix_versions: None,
                reason: refusal.to_owned(),
            });
        }

        for issue in &considered {
            if policy.fail_on_kev && issue.kev {
                violations.push(Violation {
                    rule: Rule::Kev,
                    issue_id: Some(issue.id),
                    identifier: Some(issue.identifier.clone()),
                    severity: Some(issue.severity),
                    package_name: issue.package_name.clone(),
                    fix_versions: issue.fix_versions.clone(),
                    reason: "actively exploited vulnerability (CISA KEV catalog)".to_owned(),
                });
                continue;
            }

            if let Some(threshold) = policy.fail_on_severity
                && issue.severity.is_at_least(threshold)
            {
                violations.push(Violation {
                    rule: Rule::Severity,
                    issue_id: Some(issue.id),
                    identifier: Some(issue.identifier.clone()),
                    severity: Some(issue.severity),
                    package_name: issue.package_name.clone(),
                    fix_versions: issue.fix_versions.clone(),
                    reason: format!("severity {} >= threshold {}", issue.severity.wire_name(), threshold.wire_name()),
                });
            }
        }

        if policy.fail_on_uncovered_languages && !coverage.uncovered_ecosystems.is_empty() {
            violations.push(Violation {
                rule: Rule::Coverage,
                issue_id: None,
                identifier: None,
                severity: None,
                package_name: None,
                fix_versions: None,
                reason: format!(
                    "no installed rule covers {} — this target's code was not examined",
                    coverage.uncovered_ecosystems.join(", ")
                ),
            });
        }

        GateVerdict {
            passed: violations.is_empty(),
            violations,
            evaluated: i32::try_from(considered.len()).unwrap_or(0),
            counts_by_severity,
        }
    }

    fn is_considered(issue: &GateIssue, policy: &GatePolicy) -> bool {
        if !issue.open {
            return false;
        }

        if let Some(type_) = issue.type_ {
            let counts = match type_.gate_participation() {
                GateParticipation::Never => false,
                GateParticipation::OnRequest => match type_ {
                    FindingType::AiReview => policy.include_ai_review,
                    FindingType::Plugin | FindingType::Imported => policy.include_plugins,
                    _ => false,
                },
                GateParticipation::Always => true,
            };
            if !counts {
                return false;
            }
        }

        if !policy.include_triaged
            && let Some(triage) = issue.triage
            && triage.is_settled()
        {
            return false;
        }

        if policy.fixable_only && !issue.has_published_fix() {
            return false;
        }

        true
    }

    /// A policy requested by a caller can only tighten the stored one.
    pub fn harden(base: GatePolicy, requested: &RequestedPolicy) -> Hardened {
        let mut policy = base.clone();
        let mut ignored_relaxations = Vec::new();

        match requested.fail_on_severity {
            SeverityRequest::Unset => {
                // Nothing said, nothing to weigh.
            }
            SeverityRequest::Disabled => {
                // Removing the rule is a relaxation — unless there was no rule to remove.
                if base.fail_on_severity.is_some() {
                    ignored_relaxations.push("fail_on_severity".to_owned());
                }
            }
            SeverityRequest::Threshold(wanted) => {
                if base.fail_on_severity.is_none() {
                    // Adding a rule where there was none is a tightening.
                    policy = policy.with_fail_on_severity(Some(wanted));
                } else if let Some(base_thresh) = base.fail_on_severity {
                    if wanted.is_stricter_threshold_than(base_thresh) {
                        policy = policy.with_fail_on_severity(Some(wanted));
                    } else if wanted != base_thresh {
                        ignored_relaxations.push("fail_on_severity".to_owned());
                    }
                }
            }
        }

        for flag in PolicyFlag::ALL {
            if let Some(&wanted) = requested.flags.get(&flag) {
                if wanted == policy.flag(flag) {
                    continue;
                }
                if wanted == flag.strict_value() {
                    policy = policy.with_flag(flag, wanted);
                } else {
                    ignored_relaxations.push(flag.wire_name().to_owned());
                }
            }
        }

        Hardened { policy, ignored_relaxations }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_only_tightens() {
        let base = GatePolicy::BUILT_IN; // High, KEV true, fixable false
        let mut req = RequestedPolicy::none();
        // Try to loosen KEV
        req = req.with_flag(PolicyFlag::FailOnKev, false);
        // Try to loosen severity threshold (Critical is looser than High!)
        req = req.with_severity(SeverityRequest::Threshold(Severity::Critical));

        let hardened = PolicyGate::harden(base.clone(), &req);
        assert!(hardened.policy.fail_on_kev);
        assert_eq!(hardened.policy.fail_on_severity, Some(Severity::High));
        assert!(hardened.ignored_relaxations.contains(&"fail_on_kev".to_owned()));
        assert!(hardened.ignored_relaxations.contains(&"fail_on_severity".to_owned()));
    }
}
