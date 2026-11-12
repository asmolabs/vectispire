//! DTOs and serializations for the Gate HTTP API endpoints.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::flag::PolicyFlag;
use crate::policy::GatePolicy;
use crate::resolution::ResolvedPolicy;
use crate::service::{RegisteredVerdictItem, StoredGatePolicyView};
use crate::verdict::{GateVerdict, Violation};

/// What a caller sends to `POST /api/v1/gate`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GateRequest {
    #[serde(default)]
    pub repository_id: Option<i64>,
    #[serde(default)]
    pub container_id: Option<i64>,
    #[serde(default)]
    pub fail_on_severity: Option<String>,
    #[serde(default)]
    pub fail_on_kev: Option<bool>,
    #[serde(default)]
    pub fixable_only: Option<bool>,
    #[serde(default)]
    pub include_triaged: Option<bool>,
    #[serde(default)]
    pub include_ai_review: Option<bool>,
    #[serde(default)]
    pub include_plugins: Option<bool>,
}

/// Applied policy serialized in camelCase within `GateResponse`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppliedPolicy {
    pub fail_on_severity: Option<String>,
    pub fail_on_kev: bool,
    pub fixable_only: bool,
    pub include_triaged: bool,
    pub include_ai_review: bool,
    pub fail_on_uncovered_languages: bool,
    pub include_plugins: bool,
    pub source: String,
    pub version: Option<i32>,
    pub description: Option<String>,
}

impl AppliedPolicy {
    pub fn of(resolved: &ResolvedPolicy) -> Self {
        let policy = &resolved.policy;
        Self {
            fail_on_severity: policy.fail_on_severity.map(|s| s.wire_name().to_owned()),
            fail_on_kev: policy.flag(PolicyFlag::FailOnKev),
            fixable_only: policy.flag(PolicyFlag::FixableOnly),
            include_triaged: policy.flag(PolicyFlag::IncludeTriaged),
            include_ai_review: policy.flag(PolicyFlag::IncludeAiReview),
            fail_on_uncovered_languages: policy.flag(PolicyFlag::FailOnUncoveredLanguages),
            include_plugins: policy.flag(PolicyFlag::IncludePlugins),
            source: resolved.source.wire_name().to_owned(),
            version: resolved.version,
            description: Some(resolved.describe_source()),
        }
    }
}

/// A gate violation as the wire spells it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViolationView {
    pub rule: String,
    pub issue_id: Option<i64>,
    pub identifier: Option<String>,
    pub severity: Option<String>,
    #[serde(rename = "package")]
    pub package_name: Option<String>,
    pub fix_versions: Option<String>,
    pub reason: Option<String>,
}

impl ViolationView {
    pub fn of(violation: &Violation) -> Self {
        Self {
            rule: violation.rule.wire_name().to_owned(),
            issue_id: violation.issue_id,
            identifier: violation.identifier.clone(),
            severity: violation.severity.map(|s| s.wire_name().to_owned()),
            package_name: violation.package_name.clone(),
            fix_versions: violation.fix_versions.clone(),
            reason: Some(violation.reason.clone()),
        }
    }

    pub fn list_of(violations: &[Violation]) -> Vec<Self> {
        violations.iter().map(Self::of).collect()
    }
}

/// Response returned by `POST /api/v1/gate`.
#[derive(Debug, Clone, Serialize)]
pub struct GateResponse {
    pub passed: bool,
    pub evaluated: i32,
    pub counts_by_severity: HashMap<String, i64>,
    pub violations: Vec<ViolationView>,
    pub policy: AppliedPolicy,
    pub ignored_relaxations: Vec<String>,
}

impl GateResponse {
    pub fn new(verdict: &GateVerdict, resolved: &ResolvedPolicy) -> Self {
        let mut counts = HashMap::new();
        for (sev, count) in &verdict.counts_by_severity {
            counts.insert(sev.wire_name().to_owned(), *count);
        }
        Self {
            passed: verdict.passed,
            evaluated: verdict.evaluated,
            counts_by_severity: counts,
            violations: ViolationView::list_of(&verdict.violations),
            policy: AppliedPolicy::of(resolved),
            ignored_relaxations: resolved.ignored_relaxations.clone(),
        }
    }
}

/// A registered gate verdict entry in `GET /api/v1/gate/verdicts`.
#[derive(Debug, Clone, Serialize)]
pub struct RegisteredVerdict {
    pub id: String,
    pub target_kind: Option<String>,
    pub target_id: Option<i64>,
    pub target_name: Option<String>,
    pub passed: bool,
    pub evaluated: i32,
    pub violations: i32,
    pub counts_by_severity: HashMap<String, i64>,
    pub fail_on_severity: Option<String>,
    pub policy_source: Option<String>,
    pub policy_version: Option<i64>,
    pub relaxations_ignored: bool,
    pub decided_at: Option<String>,
    pub decided_by: Option<String>,
}

impl RegisteredVerdict {
    pub fn of(item: &RegisteredVerdictItem) -> Self {
        let row = &item.verdict;
        let is_repository = row.repo_id.is_some();
        let is_container = !is_repository && row.container_id.is_some();

        let mut counts = HashMap::new();
        counts.insert("critical".to_owned(), row.critical_count);
        counts.insert("high".to_owned(), row.high_count);
        counts.insert("medium".to_owned(), row.medium_count);
        counts.insert("low".to_owned(), row.low_count);

        Self {
            id: row.id.to_string(),
            target_kind: if is_repository {
                Some("REPOSITORY".to_owned())
            } else if is_container {
                Some("CONTAINER".to_owned())
            } else {
                None
            },
            target_id: if is_repository { row.repo_id } else { row.container_id },
            target_name: item.target_name.clone(),
            passed: row.passed,
            evaluated: row.evaluated,
            violations: row.violations,
            counts_by_severity: counts,
            fail_on_severity: row.fail_on_severity.clone(),
            policy_source: Some(row.policy_source.clone()),
            policy_version: row.policy_version,
            relaxations_ignored: row.relaxations_ignored,
            decided_at: row.decided_at.format(&time::format_description::well_known::Rfc3339).ok(),
            decided_by: row.decided_by.clone(),
        }
    }
}

/// Response returned by `GET /api/v1/gate/verdicts`.
#[derive(Debug, Clone, Serialize)]
pub struct VerdictRegister {
    pub verdicts: Vec<RegisteredVerdict>,
    pub passed: i64,
    pub refused: i64,
    pub next_cursor: Option<String>,
}

/// A policy view in policy administrative endpoints (`GET /api/v1/gate/policies`, `PUT ...`).
#[derive(Debug, Clone, Serialize)]
pub struct GatePolicyView {
    pub kind: String,
    pub target_id: Option<i64>,
    pub target_name: Option<String>,
    pub version: i32,
    pub fail_on_severity: Option<String>,
    pub fail_on_kev: bool,
    pub fixable_only: bool,
    pub include_triaged: bool,
    pub include_ai_review: bool,
    pub fail_on_uncovered_languages: bool,
    pub include_plugins: bool,
    pub note: Option<String>,
    pub created_by: Option<String>,
    pub created_at: Option<String>,
}

impl GatePolicyView {
    pub fn of(stored: &StoredGatePolicyView, target_name: Option<String>) -> Self {
        let is_global = stored.target_kind == "global";
        Self {
            kind: stored.target_kind.clone(),
            target_id: if is_global { None } else { stored.target_id },
            target_name: if is_global { None } else { target_name },
            version: stored.version,
            fail_on_severity: stored.policy.fail_on_severity.map(|s| s.wire_name().to_owned()),
            fail_on_kev: stored.policy.fail_on_kev,
            fixable_only: stored.policy.fixable_only,
            include_triaged: stored.policy.include_triaged,
            include_ai_review: stored.policy.include_ai_review,
            fail_on_uncovered_languages: stored.policy.fail_on_uncovered_languages,
            include_plugins: stored.policy.include_plugins,
            note: stored.note.clone(),
            created_by: stored.created_by.clone(),
            created_at: stored.created_at.and_then(|dt| dt.format(&time::format_description::well_known::Rfc3339).ok()),
        }
    }

    pub fn built_in() -> Self {
        let policy = GatePolicy::BUILT_IN;
        Self {
            kind: "built_in".to_owned(),
            target_id: None,
            target_name: None,
            version: 0,
            fail_on_severity: policy.fail_on_severity.map(|s| s.wire_name().to_owned()),
            fail_on_kev: policy.fail_on_kev,
            fixable_only: policy.fixable_only,
            include_triaged: policy.include_triaged,
            include_ai_review: policy.include_ai_review,
            fail_on_uncovered_languages: policy.fail_on_uncovered_languages,
            include_plugins: policy.include_plugins,
            note: None,
            created_by: None,
            created_at: None,
        }
    }
}

/// Response returned by `GET /api/v1/gate/policies`.
#[derive(Debug, Clone, Serialize)]
pub struct PoliciesResponse {
    pub policies: Vec<GatePolicyView>,
    pub built_in: GatePolicyView,
}

/// Request body for storing a policy (`PUT /api/v1/gate/policies/global` and `PUT /api/v1/gate/policies/{kind}/{id}`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyRequest {
    #[serde(default)]
    pub fail_on_severity: Option<String>,
    #[serde(default)]
    pub fail_on_kev: Option<bool>,
    #[serde(default)]
    pub fixable_only: Option<bool>,
    #[serde(default)]
    pub include_triaged: Option<bool>,
    #[serde(default)]
    pub include_ai_review: Option<bool>,
    #[serde(default)]
    pub fail_on_uncovered_languages: Option<bool>,
    #[serde(default)]
    pub include_plugins: Option<bool>,
    #[serde(default)]
    pub note: Option<String>,
}

/// The response for `GET /api/v1/security/overview`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityOverviewView {
    pub targets: Vec<TargetView>,
    pub failing_count: i32,
    pub total_count: i32,
    pub kev_count: i64,
    pub never_scanned_count: i64,
    pub last_scan_failed_count: i64,
}

impl SecurityOverviewView {
    pub fn of(overview: &crate::overview::Overview) -> Self {
        let targets = overview
            .targets
            .iter()
            .map(|posture| {
                let (kind, target_id) = match posture.target {
                    crate::ScanTarget::Repository(id) => ("repository", id),
                    crate::ScanTarget::Container(id) => ("container", id),
                };
                let mut counts = HashMap::new();
                for (sev, count) in &posture.verdict.counts_by_severity {
                    counts.insert(sev.wire_name().to_owned(), *count);
                }
                TargetView {
                    kind: kind.to_owned(),
                    target_id,
                    name: posture.name.clone(),
                    verdict: VerdictView {
                        passed: posture.verdict.passed,
                        evaluated: posture.verdict.evaluated,
                        violations: ViolationView::list_of(&posture.verdict.violations),
                        counts_by_severity: counts,
                    },
                    policy: OverviewPolicyView {
                        source: posture.policy.source.wire_name().to_owned(),
                        version: posture.policy.version,
                    },
                    observation: posture.observation.wire_name().to_owned(),
                    last_scan_at: posture
                        .last_scan
                        .as_ref()
                        .and_then(|s| s.created_at.format(&time::format_description::well_known::Rfc3339).ok()),
                    last_scan_id: posture.last_scan.as_ref().map(|s| s.id),
                    passed: posture.passed,
                    observed: posture.observed,
                }
            })
            .collect();

        Self {
            targets,
            failing_count: overview.failing_count,
            total_count: overview.total_count,
            kev_count: overview.kev_count,
            never_scanned_count: overview.never_scanned_count,
            last_scan_failed_count: overview.last_scan_failed_count,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetView {
    pub kind: String,
    pub target_id: i64,
    pub name: String,
    pub verdict: VerdictView,
    pub policy: OverviewPolicyView,
    pub observation: String,
    pub last_scan_at: Option<String>,
    pub last_scan_id: Option<i64>,
    pub passed: bool,
    pub observed: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerdictView {
    pub passed: bool,
    pub evaluated: i32,
    pub violations: Vec<ViolationView>,
    pub counts_by_severity: HashMap<String, i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewPolicyView {
    pub source: String,
    pub version: Option<i32>,
}
