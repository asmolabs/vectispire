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
    #[serde(rename = "oldVersion")]
    pub previous_version: Option<String>,
    #[serde(rename = "newVersion")]
    pub new_version: Option<String>,
    #[serde(rename = "oldLicense")]
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
    #[serde(rename = "cveId")]
    pub identifier: String,
    pub severity: Option<String>,
    #[serde(rename = "packageName")]
    pub package_name: Option<String>,
    #[serde(rename = "version")]
    pub package_version: Option<String>,
    pub status: CveDeltaStatus,
}

/// Java's `SbomDiffReport`, field for field on the wire: `addedCount`…`resolvedCveCount`, a delta's `oldVersion` and
/// `oldLicense`, a CVE's `cveId` and `version`. Every one of those went out under another name (`added`,
/// `previousVersion`, `identifier`…), which no client of the contract reads — the diff showed no figure and no CVE.
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
    #[serde(rename = "addedCount")]
    pub added: i32,
    #[serde(rename = "removedCount")]
    pub removed: i32,
    #[serde(rename = "versionChangedCount")]
    pub version_changed: i32,
    #[serde(rename = "licenseChangedCount")]
    pub license_changed: i32,
    #[serde(rename = "introducedCveCount")]
    pub introduced_cves: i32,
    #[serde(rename = "resolvedCveCount")]
    pub resolved_cves: i32,
    #[serde(rename = "componentDeltas")]
    pub component_deltas: Vec<ComponentDelta>,
    #[serde(rename = "cveDeltas")]
    pub cve_deltas: Vec<CveDelta>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every member Java's `SbomDiffReport`, `ComponentDelta` and `CveDelta` carry, by its name on the wire.
    #[test]
    fn the_diff_goes_out_under_java_s_names() {
        let report = SbomDiffReport {
            from_scan_id: 1,
            to_scan_id: 2,
            from_version: "1".into(),
            to_version: "2".into(),
            added: 1,
            removed: 2,
            version_changed: 3,
            license_changed: 4,
            introduced_cves: 5,
            resolved_cves: 6,
            component_deltas: vec![ComponentDelta {
                name: "commons-io".into(),
                purl: None,
                r#type: None,
                is_direct: None,
                previous_version: Some("2.10.0".into()),
                new_version: Some("2.11.0".into()),
                previous_license: Some("MIT".into()),
                new_license: None,
                change_type: ComponentChangeType::VersionChanged,
            }],
            cve_deltas: vec![CveDelta {
                identifier: "CVE-2021-29425".into(),
                severity: None,
                package_name: None,
                package_version: Some("2.10.0".into()),
                status: CveDeltaStatus::Resolved,
            }],
        };
        let json = serde_json::to_value(&report).unwrap();
        for (member, value) in [
            ("addedCount", 1),
            ("removedCount", 2),
            ("versionChangedCount", 3),
            ("licenseChangedCount", 4),
            ("introducedCveCount", 5),
            ("resolvedCveCount", 6),
        ] {
            assert_eq!(json[member], value, "{member}");
        }
        assert_eq!(json["componentDeltas"][0]["oldVersion"], "2.10.0");
        assert_eq!(json["componentDeltas"][0]["oldLicense"], "MIT");
        assert_eq!(json["cveDeltas"][0]["cveId"], "CVE-2021-29425");
        assert_eq!(json["cveDeltas"][0]["version"], "2.10.0");
    }
}
