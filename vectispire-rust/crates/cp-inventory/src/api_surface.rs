//! API attack surface models: shadow API detection, posture summaries, and operation IDs.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;
use vectispire_protocol::{ApiContract, ApiEndpoint, ApiVisibility};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ShadowApiStatus {
    Documented,
    ShadowApi,
    Undocumented,
}

impl ShadowApiStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ShadowApiStatus::Documented => "DOCUMENTED",
            ShadowApiStatus::ShadowApi => "SHADOW_API",
            ShadowApiStatus::Undocumented => "UNDOCUMENTED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowApiDiff {
    pub documented_endpoints: Vec<ApiEndpoint>,
    pub shadow_endpoints: Vec<ApiEndpoint>,
    pub zombie_endpoints: Vec<String>,
}

impl ShadowApiDiff {
    pub fn compute(code_endpoints: &[ApiEndpoint], contracts: &[ApiContract]) -> Self {
        if contracts.is_empty() {
            return ShadowApiDiff {
                documented_endpoints: Vec::new(),
                shadow_endpoints: code_endpoints.to_vec(),
                zombie_endpoints: Vec::new(),
            };
        }

        let mut declared_paths = HashSet::new();
        for contract in contracts {
            for p in contract.declared_paths.iter().flatten() {
                declared_paths.insert(normalize_path(p));
            }
        }

        let mut documented = Vec::new();
        let mut shadow = Vec::new();
        let mut matched_declared_paths = HashSet::new();

        for ep in code_endpoints {
            let norm = normalize_path(&ep.path);
            if matches_any_declared(&norm, &declared_paths, &mut matched_declared_paths) {
                documented.push(ep.clone());
            } else {
                shadow.push(ep.clone());
            }
        }

        let mut zombie = Vec::new();
        for dec in declared_paths {
            if !matched_declared_paths.contains(&dec) {
                zombie.push(dec);
            }
        }

        ShadowApiDiff { documented_endpoints: documented, shadow_endpoints: shadow, zombie_endpoints: zombie }
    }
}

fn matches_any_declared(code_path: &str, declared_paths: &HashSet<String>, matched: &mut HashSet<String>) -> bool {
    if declared_paths.contains(code_path) {
        matched.insert(code_path.to_owned());
        return true;
    }

    let code_pattern = to_param_regex(code_path);
    let code_re = regex::Regex::new(&code_pattern).ok();

    for dec in declared_paths {
        if let Some(ref re) = code_re
            && re.is_match(dec)
        {
            matched.insert(dec.clone());
            return true;
        }
        let dec_pattern = to_param_regex(dec);
        if let Ok(dec_re) = regex::Regex::new(&dec_pattern)
            && dec_re.is_match(code_path)
        {
            matched.insert(dec.clone());
            return true;
        }
    }
    false
}

pub fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/".to_owned();
    }
    let mut rooted = if !trimmed.starts_with('/') { format!("/{trimmed}") } else { trimmed.to_owned() };
    if rooted.len() > 1 && rooted.ends_with('/') {
        rooted.pop();
    }
    rooted
}

fn to_param_regex(path: &str) -> String {
    static RE_CURLY: std::sync::LazyLock<Option<regex::Regex>> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\{[^/]+\}").ok());
    static RE_COLON: std::sync::LazyLock<Option<regex::Regex>> =
        std::sync::LazyLock::new(|| regex::Regex::new(r":[a-zA-Z0-9_]+").ok());

    let replaced_curly = match RE_CURLY.as_ref() {
        Some(re) => re.replace_all(path, "[^/]+").into_owned(),
        None => path.to_owned(),
    };
    let replaced_colon = match RE_COLON.as_ref() {
        Some(re) => re.replace_all(&replaced_curly, "[^/]+").into_owned(),
        None => replaced_curly,
    };
    format!("^{}$", replaced_colon)
}

pub fn is_sensitive_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/admin")
        || lower.contains("/actuator")
        || lower.contains("/debug")
        || lower.contains("/metrics")
        || lower.contains("/env")
        || lower.contains("/internal")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackSurfaceSummary {
    #[serde(rename = "totalEndpoints")]
    pub total_endpoints: i32,
    #[serde(rename = "publicEndpoints")]
    pub public_endpoints: i32,
    #[serde(rename = "internalEndpoints")]
    pub internal_endpoints: i32,
    #[serde(rename = "unauthenticatedEndpoints")]
    pub unauthenticated_endpoints: i32,
    #[serde(rename = "shadowEndpoints")]
    pub shadow_endpoints: i32,
    #[serde(rename = "sensitiveUnprotectedEndpoints")]
    pub sensitive_unprotected_endpoints: i32,
}

impl AttackSurfaceSummary {
    pub fn from(endpoints: &[ApiEndpoint], diff: Option<&ShadowApiDiff>) -> Self {
        let total = i32::try_from(endpoints.len()).unwrap_or(i32::MAX);
        let mut pub_count: i32 = 0;
        let mut intern_count: i32 = 0;
        let mut unauth_count: i32 = 0;
        let mut sensitive_unprot: i32 = 0;

        for ep in endpoints {
            match ep.visibility {
                ApiVisibility::Public => pub_count = pub_count.saturating_add(1),
                ApiVisibility::Internal => intern_count = intern_count.saturating_add(1),
                ApiVisibility::Unknown => {}
            }

            if !ep.auth_required {
                unauth_count = unauth_count.saturating_add(1);
                if is_sensitive_path(&ep.path) {
                    sensitive_unprot = sensitive_unprot.saturating_add(1);
                }
            }
        }

        let shadow = diff.and_then(|d| i32::try_from(d.shadow_endpoints.len()).ok()).unwrap_or(0);

        Self {
            total_endpoints: total,
            public_endpoints: pub_count,
            internal_endpoints: intern_count,
            unauthenticated_endpoints: unauth_count,
            shadow_endpoints: shadow,
            sensitive_unprotected_endpoints: sensitive_unprot,
        }
    }
}

#[derive(Default, Debug)]
pub struct OperationIds {
    taken: HashSet<String>,
    next_suffix: HashMap<String, usize>,
}

impl OperationIds {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn claim(&mut self, base: &str) -> String {
        if self.taken.insert(base.to_owned()) {
            return base.to_owned();
        }
        let mut n = *self.next_suffix.get(base).unwrap_or(&2);
        loop {
            let candidate = format!("{base}_{n}");
            if self.taken.insert(candidate.clone()) {
                self.next_suffix.insert(base.to_owned(), n.saturating_add(1));
                return candidate;
            }
            n = n.saturating_add(1);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointView {
    pub id: Option<i64>,
    #[serde(rename = "scanId")]
    pub scan_id: Option<i64>,
    #[serde(rename = "repositoryId")]
    pub repository_id: Option<i64>,
    pub method: String,
    pub path: String,
    #[serde(rename = "authRequired")]
    pub auth_required: bool,
    #[serde(rename = "authType")]
    pub auth_type: Option<String>,
    pub visibility: String,
    #[serde(rename = "filePath")]
    pub file_path: Option<String>,
    #[serde(rename = "lineNumber")]
    pub line_number: Option<i32>,
    pub framework: Option<String>,
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub tags: Option<String>,
    #[serde(rename = "shadowStatus")]
    pub shadow_status: String,
    #[serde(rename = "createdAt", with = "time::serde::iso8601")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiContractView {
    pub id: Option<i64>,
    #[serde(rename = "repositoryId")]
    pub repository_id: Option<i64>,
    #[serde(rename = "scanId")]
    pub scan_id: Option<i64>,
    #[serde(rename = "contractPath")]
    pub contract_path: String,
    pub format: Option<String>,
    pub title: Option<String>,
    pub version: Option<String>,
    #[serde(rename = "endpointsCount")]
    pub endpoints_count: i32,
    #[serde(rename = "createdAt", with = "time::serde::iso8601")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryApisOverview {
    #[serde(rename = "repositoryId")]
    pub repository_id: i64,
    pub endpoints: Vec<EndpointView>,
    pub contracts: Vec<ApiContractView>,
    pub summary: AttackSurfaceSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalAttackSurface {
    #[serde(rename = "totalEndpoints")]
    pub total_endpoints: i32,
    #[serde(rename = "publicEndpoints")]
    pub public_endpoints: i32,
    #[serde(rename = "internalEndpoints")]
    pub internal_endpoints: i32,
    #[serde(rename = "unauthenticatedEndpoints")]
    pub unauthenticated_endpoints: i32,
    #[serde(rename = "shadowEndpoints")]
    pub shadow_endpoints: i32,
    #[serde(rename = "sensitiveUnprotectedEndpoints")]
    pub sensitive_unprotected_endpoints: i32,
    pub frameworks: Vec<String>,
    #[serde(rename = "highRiskEndpoints")]
    pub high_risk_endpoints: Vec<EndpointView>,
    #[serde(rename = "allEndpoints")]
    pub all_endpoints: Vec<EndpointView>,
}
