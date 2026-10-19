//! SBOM and vulnerability difference models between two scans.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentChangeType {
    Added,
    Removed,
    VersionChanged,
    LicenseChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentDelta {
    pub name: String,
    pub purl: Option<String>,
    pub r#type: Option<String>,
    #[serde(rename = "isDirect")]
    pub is_direct: Option<bool>,
    #[serde(rename = "previousVersion")]
    pub previous_version: Option<String>,
    #[serde(rename = "newVersion")]
    pub new_version: Option<String>,
    #[serde(rename = "previousLicense")]
    pub previous_license: Option<String>,
    #[serde(rename = "newLicense")]
    pub new_license: Option<String>,
    #[serde(rename = "changeType")]
    pub change_type: ComponentChangeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CveDeltaStatus {
    Introduced,
    Persistent,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CveDelta {
    pub identifier: String,
    pub severity: Option<String>,
    #[serde(rename = "packageName")]
    pub package_name: Option<String>,
    #[serde(rename = "packageVersion")]
    pub package_version: Option<String>,
    pub status: CveDeltaStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomDiffReport {
    #[serde(rename = "fromScanId")]
    pub from_scan_id: i64,
    #[serde(rename = "toScanId")]
    pub to_scan_id: i64,
    #[serde(rename = "fromVersion")]
    pub from_version: String,
    #[serde(rename = "toVersion")]
    pub to_version: String,
    pub added: i32,
    pub removed: i32,
    #[serde(rename = "versionChanged")]
    pub version_changed: i32,
    #[serde(rename = "licenseChanged")]
    pub license_changed: i32,
    #[serde(rename = "introducedCves")]
    pub introduced_cves: i32,
    #[serde(rename = "resolvedCves")]
    pub resolved_cves: i32,
    #[serde(rename = "componentDeltas")]
    pub component_deltas: Vec<ComponentDelta>,
    #[serde(rename = "cveDeltas")]
    pub cve_deltas: Vec<CveDelta>,
}
