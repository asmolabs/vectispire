//! Blast radius analysis and risk scoring models.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub r#type: String, // "TARGET", "PACKAGE", "CVE"
    pub version: Option<String>,
    pub ecosystem: Option<String>,
    pub score: i32,
    #[serde(rename = "isDirect")]
    pub is_direct: bool,
    pub cves: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub relationship: String, // "DIRECT_DEPENDENCY", "TRANSITIVE_DEPENDENCY", "AFFECTED_BY"
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastDependencyGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetImpact {
    #[serde(rename = "targetId")]
    pub target_id: Option<i64>,
    #[serde(rename = "targetKind")]
    pub target_kind: String, // "REPOSITORY" or "CONTAINER"
    #[serde(rename = "targetName")]
    pub target_name: String,
    #[serde(rename = "targetContext")]
    pub target_context: String,
    #[serde(rename = "sourceFile")]
    pub source_file: String,
    pub purl: Option<String>,
    #[serde(rename = "packageName")]
    pub package_name: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "isDirect")]
    pub is_direct: bool,
    pub cves: Vec<String>,
    #[serde(rename = "scanId")]
    pub scan_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopImpactPackage {
    #[serde(rename = "packageName")]
    pub package_name: String,
    pub ecosystem: String,
    #[serde(rename = "affectedTargetsCount")]
    pub affected_targets_count: i32,
    #[serde(rename = "directUsages")]
    pub direct_usages: i32,
    #[serde(rename = "transitiveUsages")]
    pub transitive_usages: i32,
    #[serde(rename = "totalCves")]
    pub total_cves: i32,
    #[serde(rename = "maxCvss")]
    pub max_cvss: f64,
    #[serde(rename = "blastRadiusScore")]
    pub blast_radius_score: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadiusReport {
    pub query: String,
    #[serde(rename = "queryType")]
    pub query_type: String, // "PACKAGE" or "CVE"
    #[serde(rename = "totalTargetsAffected")]
    pub total_targets_affected: i32,
    #[serde(rename = "directUsages")]
    pub direct_usages: i32,
    #[serde(rename = "transitiveUsages")]
    pub transitive_usages: i32,
    #[serde(rename = "totalAssociatedCves")]
    pub total_associated_cves: i32,
    #[serde(rename = "blastRadiusScore")]
    pub blast_radius_score: i32,
    pub targets: Vec<TargetImpact>,
    pub graph: BlastDependencyGraph,
}

impl BlastRadiusReport {
    pub fn calculate_score(
        targets_count: i32,
        direct_count: i32,
        transitive_count: i32,
        _cve_count: i32,
        max_cvss: f64,
    ) -> i32 {
        if targets_count <= 0 {
            return 0;
        }

        let dispersion_weight = (targets_count as f64 * 8.0).min(40.0);
        let direct_weight = (direct_count as f64 * 10.0 + transitive_count as f64 * 2.0).min(20.0);
        let severity_weight = (max_cvss / 10.0) * 40.0;

        let total = (dispersion_weight + direct_weight + severity_weight).min(100.0);
        format!("{:.0}", total).parse::<i32>().unwrap_or(0)
    }
}

pub fn extract_ecosystem(purl: Option<&str>) -> String {
    let Some(purl) = purl else {
        return "Generic".to_owned();
    };
    if purl.starts_with("pkg:maven") {
        "Maven".to_owned()
    } else if purl.starts_with("pkg:npm") {
        "npm".to_owned()
    } else if purl.starts_with("pkg:pypi") {
        "PyPI".to_owned()
    } else if purl.starts_with("pkg:golang") {
        "Go".to_owned()
    } else if purl.starts_with("pkg:apk") {
        "Alpine".to_owned()
    } else if purl.starts_with("pkg:deb") {
        "Debian".to_owned()
    } else if purl.starts_with("pkg:docker") || purl.starts_with("pkg:oci") {
        "OCI".to_owned()
    } else {
        "Generic".to_owned()
    }
}
