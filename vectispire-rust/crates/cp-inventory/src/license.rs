//! Open-source license governance, risk categories, compliance policy, and compatibility conflict evaluation.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LicenseRiskCategory {
    Permissive,
    WeakCopyleft,
    StrongCopyleft,
    Forbidden,
    Unknown,
}

/// The wire name, `STRONG_COPYLEFT` — what Java's `enum.toString()` prints into a sentence. Without it, a
/// `{:?}` wrote `StrongCopyleft` into every licence violation's reason.
impl std::fmt::Display for LicenseRiskCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl LicenseRiskCategory {
    pub const ALL: [LicenseRiskCategory; 5] = [
        LicenseRiskCategory::Permissive,
        LicenseRiskCategory::WeakCopyleft,
        LicenseRiskCategory::StrongCopyleft,
        LicenseRiskCategory::Forbidden,
        LicenseRiskCategory::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            LicenseRiskCategory::Permissive => "PERMISSIVE",
            LicenseRiskCategory::WeakCopyleft => "WEAK_COPYLEFT",
            LicenseRiskCategory::StrongCopyleft => "STRONG_COPYLEFT",
            LicenseRiskCategory::Forbidden => "FORBIDDEN",
            LicenseRiskCategory::Unknown => "UNKNOWN",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "PERMISSIVE" => Some(LicenseRiskCategory::Permissive),
            "WEAK_COPYLEFT" => Some(LicenseRiskCategory::WeakCopyleft),
            "STRONG_COPYLEFT" => Some(LicenseRiskCategory::StrongCopyleft),
            "FORBIDDEN" => Some(LicenseRiskCategory::Forbidden),
            "UNKNOWN" => Some(LicenseRiskCategory::Unknown),
            _ => None,
        }
    }

    pub fn classify(license_expression: &str) -> Self {
        let trimmed = license_expression.trim();
        if trimmed.is_empty() {
            return LicenseRiskCategory::Unknown;
        }

        let normalized = trimmed.to_ascii_uppercase().replace(['(', ')'], "");
        let norm = normalized.trim();

        const FORBIDDEN_LICENSES: &[&str] = &[
            "COMMERCIAL",
            "PROPRIETARY",
            "NON-COMMERCIAL",
            "CC-BY-NC-4.0",
            "CC-BY-NC-3.0",
            "CC-BY-NC-2.0",
            "BUSL-1.1",
            "COMMONS-CLAUSE",
            "SEE-LICENSE-IN-LICENSE",
            "UNLICENSED",
        ];

        const STRONG_COPYLEFT_LICENSES: &[&str] = &[
            "GPL-1.0-ONLY",
            "GPL-1.0-OR-LATER",
            "GPL-2.0-ONLY",
            "GPL-2.0-OR-LATER",
            "GPL-3.0-ONLY",
            "GPL-3.0-OR-LATER",
            "GPL-1.0",
            "GPL-2.0",
            "GPL-3.0",
            "AGPL-1.0",
            "AGPL-3.0",
            "AGPL-3.0-ONLY",
            "AGPL-3.0-OR-LATER",
            "SSPL-1.0",
            "EUPL-1.1",
            "EUPL-1.2",
            "OSL-1.0",
            "OSL-2.0",
            "OSL-3.0",
            "CPAL-1.0",
            "QPL-1.0",
            "RPL-1.5",
            "SLEEPYCAT",
            "CECILL-2.1",
        ];

        const WEAK_COPYLEFT_LICENSES: &[&str] = &[
            "LGPL-2.0-ONLY",
            "LGPL-2.0-OR-LATER",
            "LGPL-2.1-ONLY",
            "LGPL-2.1-OR-LATER",
            "LGPL-3.0-ONLY",
            "LGPL-3.0-OR-LATER",
            "LGPL-2.0",
            "LGPL-2.1",
            "LGPL-3.0",
            "MPL-1.0",
            "MPL-1.1",
            "MPL-2.0",
            "CDDL-1.0",
            "CDDL-1.1",
            "EPL-1.0",
            "EPL-2.0",
            "CPL-1.0",
            "APSL-2.0",
            "MS-PL",
            "MS-RL",
            "IPA",
            "SUNPRO",
        ];

        const PERMISSIVE_LICENSES: &[&str] = &[
            "MIT",
            "APACHE-2.0",
            "APACHE-1.1",
            "APACHE-2.0-WITH-LLVM-EXCEPTION",
            "BSD-2-CLAUSE",
            "BSD-3-CLAUSE",
            "BSD-4-CLAUSE",
            "ISC",
            "CC0-1.0",
            "UNLICENSE",
            "0BSD",
            "ZLIB",
            "POSTGRESQL",
            "WTFPL",
            "JSON",
            "PYTHON-2.0",
            "ARTISTIC-2.0",
            "RUBY",
            "OPENSSL",
            "ECL-2.0",
            "UPL-1.0",
            "BSL-1.0",
            "BLUEOAK-1.0.0",
            "X11",
            "FREEIMAGE",
            "OFL-1.1",
            "EDL-1.0",
            "CC-BY-4.0",
            "CC-BY-3.0",
        ];

        if FORBIDDEN_LICENSES.contains(&norm)
            || norm.contains("PROPRIETARY")
            || norm.contains("NON-COMMERCIAL")
            || norm.contains("COMMONS-CLAUSE")
        {
            return LicenseRiskCategory::Forbidden;
        }

        if STRONG_COPYLEFT_LICENSES.contains(&norm)
            || norm.starts_with("GPL")
            || norm.starts_with("AGPL")
            || norm.starts_with("SSPL")
            || norm.starts_with("EUPL")
        {
            return LicenseRiskCategory::StrongCopyleft;
        }

        if WEAK_COPYLEFT_LICENSES.contains(&norm)
            || norm.starts_with("LGPL")
            || norm.starts_with("MPL")
            || norm.starts_with("EPL")
            || norm.starts_with("CDDL")
        {
            return LicenseRiskCategory::WeakCopyleft;
        }

        if PERMISSIVE_LICENSES.contains(&norm)
            || norm.contains("MIT")
            || norm.contains("APACHE")
            || norm.contains("BSD")
            || norm.contains("ISC")
            || norm.contains("BOOST")
            || norm.contains("ZLIB")
        {
            return LicenseRiskCategory::Permissive;
        }

        LicenseRiskCategory::Unknown
    }
}

/// Policy governing allowed license categories and exemptions.
///
/// **Normalised on construction, from the wire too** (Java's compact constructor): this is the body of
/// `PUT /licenses/policy`, and a missing list, a `null` one or a `null` entry is no entry — they were refused as a
/// malformed body, where Java stores the policy. Identifiers are trimmed and in capitals, blanks dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "LicensePolicyOnTheWire")]
pub struct LicensePolicy {
    #[serde(default, rename = "disallowedCategories")]
    pub disallowed_categories: BTreeSet<LicenseRiskCategory>,
    #[serde(default, rename = "explicitlyAllowedLicenses")]
    pub explicitly_allowed_licenses: BTreeSet<String>,
    #[serde(default, rename = "explicitlyDisallowedLicenses")]
    pub explicitly_disallowed_licenses: BTreeSet<String>,
}

impl LicensePolicy {
    pub fn new(
        disallowed_categories: impl IntoIterator<Item = LicenseRiskCategory>,
        explicitly_allowed_licenses: impl IntoIterator<Item = impl AsRef<str>>,
        explicitly_disallowed_licenses: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        let cats = disallowed_categories.into_iter().collect();
        let allowed = explicitly_allowed_licenses
            .into_iter()
            .map(|s| s.as_ref().trim().to_uppercase())
            .filter(|s| !s.is_empty())
            .collect();
        let disallowed = explicitly_disallowed_licenses
            .into_iter()
            .map(|s| s.as_ref().trim().to_uppercase())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            disallowed_categories: cats,
            explicitly_allowed_licenses: allowed,
            explicitly_disallowed_licenses: disallowed,
        }
    }

    pub fn default_policy() -> Self {
        let mut cats = BTreeSet::new();
        cats.insert(LicenseRiskCategory::StrongCopyleft);
        cats.insert(LicenseRiskCategory::Forbidden);
        Self {
            disallowed_categories: cats,
            explicitly_allowed_licenses: BTreeSet::new(),
            explicitly_disallowed_licenses: BTreeSet::new(),
        }
    }

    pub fn is_compliant(&self, license: Option<&str>, category: LicenseRiskCategory) -> bool {
        let normalized = license.map(|l| l.trim().to_uppercase());
        if let Some(ref norm) = normalized {
            if self.explicitly_disallowed_licenses.contains(norm) {
                return false;
            }
            if self.explicitly_allowed_licenses.contains(norm) {
                return true;
            }
        }
        !self.disallowed_categories.contains(&category)
    }
}

/// The body as a client may send it: every list absent or `null`, any entry `null`.
#[derive(Debug, Deserialize)]
struct LicensePolicyOnTheWire {
    /// A `null` list is none, but a `null` category is refused, as Jackson refuses it into Java's `EnumSet`.
    #[serde(default, rename = "disallowedCategories")]
    disallowed_categories: Option<Vec<LicenseRiskCategory>>,
    #[serde(default, rename = "explicitlyAllowedLicenses")]
    explicitly_allowed_licenses: Option<Vec<Option<String>>>,
    #[serde(default, rename = "explicitlyDisallowedLicenses")]
    explicitly_disallowed_licenses: Option<Vec<Option<String>>>,
}

impl From<LicensePolicyOnTheWire> for LicensePolicy {
    fn from(wire: LicensePolicyOnTheWire) -> LicensePolicy {
        let entries = |list: Option<Vec<Option<String>>>| list.into_iter().flatten().flatten();
        LicensePolicy::new(
            wire.disallowed_categories.into_iter().flatten(),
            entries(wire.explicitly_allowed_licenses),
            entries(wire.explicitly_disallowed_licenses),
        )
    }
}

impl Default for LicensePolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Compatibility {
    Compatible,
    Conditional,
    IncompatibleBlocking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConflictVerdict {
    ForbiddenLicence,
    StrongCopyleftProprietary,
    StrongCopyleftReciprocal,
    WeakCopyleft,
    Permissive,
    UnknownLicence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleNote {
    PermissiveInProprietary,
    WeakCopyleftInProprietary,
    StrongCopyleftInProprietary,
    ForbiddenInProprietary,
    PermissiveInPermissive,
    WeakCopyleftInPermissive,
    StrongCopyleftInPermissive,
    PermissiveInGpl,
    StrongCopyleftInGpl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityCell {
    #[serde(rename = "targetLicenseType")]
    pub target_license_type: String,
    #[serde(rename = "dependencyLicenseCategory")]
    pub dependency_license_category: String,
    pub compatibility: Compatibility,
    pub note: RuleNote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseConflict {
    #[serde(rename = "packageName")]
    pub package_name: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "licenseExpression")]
    pub license_expression: String,
    #[serde(rename = "riskCategory")]
    pub risk_category: LicenseRiskCategory,
    #[serde(rename = "targetKind")]
    pub target_kind: String,
    /// The target's name, `null` for a repository that has none — as Java's; it was `repo-<id>`.
    #[serde(rename = "targetName")]
    pub target_name: Option<String>,
    pub compatibility: Compatibility,
    pub verdict: ConflictVerdict,
}

#[derive(Debug, Clone, Copy)]
pub struct LicenseConflictMatrix;

impl LicenseConflictMatrix {
    pub fn get_standard_compatibility_rules() -> Vec<CompatibilityCell> {
        vec![
            CompatibilityCell {
                target_license_type: "PROPRIETARY_COMMERCIAL".to_owned(),
                dependency_license_category: "PERMISSIVE".to_owned(),
                compatibility: Compatibility::Compatible,
                note: RuleNote::PermissiveInProprietary,
            },
            CompatibilityCell {
                target_license_type: "PROPRIETARY_COMMERCIAL".to_owned(),
                dependency_license_category: "WEAK_COPYLEFT".to_owned(),
                compatibility: Compatibility::Conditional,
                note: RuleNote::WeakCopyleftInProprietary,
            },
            CompatibilityCell {
                target_license_type: "PROPRIETARY_COMMERCIAL".to_owned(),
                dependency_license_category: "STRONG_COPYLEFT".to_owned(),
                compatibility: Compatibility::IncompatibleBlocking,
                note: RuleNote::StrongCopyleftInProprietary,
            },
            CompatibilityCell {
                target_license_type: "PROPRIETARY_COMMERCIAL".to_owned(),
                dependency_license_category: "FORBIDDEN".to_owned(),
                compatibility: Compatibility::IncompatibleBlocking,
                note: RuleNote::ForbiddenInProprietary,
            },
            CompatibilityCell {
                target_license_type: "OPEN_SOURCE_PERMISSIVE".to_owned(),
                dependency_license_category: "PERMISSIVE".to_owned(),
                compatibility: Compatibility::Compatible,
                note: RuleNote::PermissiveInPermissive,
            },
            CompatibilityCell {
                target_license_type: "OPEN_SOURCE_PERMISSIVE".to_owned(),
                dependency_license_category: "WEAK_COPYLEFT".to_owned(),
                compatibility: Compatibility::Conditional,
                note: RuleNote::WeakCopyleftInPermissive,
            },
            CompatibilityCell {
                target_license_type: "OPEN_SOURCE_PERMISSIVE".to_owned(),
                dependency_license_category: "STRONG_COPYLEFT".to_owned(),
                compatibility: Compatibility::Conditional,
                note: RuleNote::StrongCopyleftInPermissive,
            },
            CompatibilityCell {
                target_license_type: "GPL_COMPLIANT".to_owned(),
                dependency_license_category: "PERMISSIVE".to_owned(),
                compatibility: Compatibility::Compatible,
                note: RuleNote::PermissiveInGpl,
            },
            CompatibilityCell {
                target_license_type: "GPL_COMPLIANT".to_owned(),
                dependency_license_category: "STRONG_COPYLEFT".to_owned(),
                compatibility: Compatibility::Compatible,
                note: RuleNote::StrongCopyleftInGpl,
            },
        ]
    }

    pub fn evaluate(
        package_name: &str,
        package_version: &str,
        license_expression: &str,
        target_kind: &str,
        target_name: Option<&str>,
        is_proprietary_target: bool,
    ) -> LicenseConflict {
        let category = LicenseRiskCategory::classify(license_expression);

        let (compatibility, verdict) = match category {
            LicenseRiskCategory::Forbidden => (Compatibility::IncompatibleBlocking, ConflictVerdict::ForbiddenLicence),
            LicenseRiskCategory::StrongCopyleft => {
                if is_proprietary_target {
                    (Compatibility::IncompatibleBlocking, ConflictVerdict::StrongCopyleftProprietary)
                } else {
                    (Compatibility::Conditional, ConflictVerdict::StrongCopyleftReciprocal)
                }
            }
            LicenseRiskCategory::WeakCopyleft => (Compatibility::Conditional, ConflictVerdict::WeakCopyleft),
            LicenseRiskCategory::Permissive => (Compatibility::Compatible, ConflictVerdict::Permissive),
            LicenseRiskCategory::Unknown => (Compatibility::Conditional, ConflictVerdict::UnknownLicence),
        };

        LicenseConflict {
            package_name: package_name.to_owned(),
            package_version: package_version.to_owned(),
            license_expression: license_expression.to_owned(),
            risk_category: category,
            target_kind: target_kind.to_owned(),
            target_name: target_name.map(str::to_owned),
            compatibility,
            verdict,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseEntry {
    #[serde(rename = "packageName")]
    pub package_name: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    pub purl: Option<String>,
    pub license: String,
    #[serde(rename = "riskCategory")]
    pub risk_category: LicenseRiskCategory,
    pub compliant: bool,
    #[serde(rename = "violationReason")]
    pub violation_reason: Option<String>,
    #[serde(rename = "targetId")]
    pub target_id: Option<i64>,
    #[serde(rename = "targetKind")]
    pub target_kind: String,
    /// The target's name, `null` for a repository that has none — as Java's; it was `repo-<id>`.
    #[serde(rename = "targetName")]
    pub target_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseSummary {
    #[serde(rename = "totalDependencies")]
    pub total_dependencies: i64,
    #[serde(rename = "uniqueLicenses")]
    pub unique_licenses: i64,
    #[serde(rename = "nonCompliantCount")]
    pub non_compliant_count: i64,
    #[serde(rename = "breakdownByRisk")]
    pub breakdown_by_risk: BTreeMap<LicenseRiskCategory, i64>,
}

#[derive(Debug, Clone, Copy)]
pub struct SbomLicences;

impl SbomLicences {
    pub const UNDECLARED: &'static str = "UNKNOWN";

    pub fn declared(artifact: &serde_json::Value) -> Option<String> {
        let licenses = artifact.get("licenses")?.as_array()?;
        if licenses.is_empty() {
            return None;
        }

        let mut values = Vec::new();
        for lic in licenses {
            if let Some(text) = lic.as_str() {
                if !text.is_empty() {
                    values.push(text.to_owned());
                }
            } else if let Some(obj) = lic.as_object() {
                if let Some(spdx) = obj.get("spdxExpression").and_then(|v| v.as_str()) {
                    if !spdx.is_empty() {
                        values.push(spdx.to_owned());
                    }
                } else if let Some(val) = obj.get("value").and_then(|v| v.as_str()) {
                    if !val.is_empty() {
                        values.push(val.to_owned());
                    }
                } else if let Some(license_obj) = obj.get("license").and_then(|v| v.as_object()) {
                    if let Some(id) = license_obj.get("id").and_then(|v| v.as_str()) {
                        if !id.is_empty() {
                            values.push(id.to_owned());
                        }
                    } else if let Some(name) = license_obj.get("name").and_then(|v| v.as_str())
                        && !name.is_empty()
                    {
                        values.push(name.to_owned());
                    }
                }
            }
        }

        if values.is_empty() { None } else { Some(values.join(" OR ")) }
    }

    pub fn declared_or_unknown(artifact: &serde_json::Value) -> String {
        match Self::declared(artifact) {
            Some(lic) if !lic.trim().is_empty() && !lic.eq_ignore_ascii_case(Self::UNDECLARED) => lic,
            _ => Self::UNDECLARED.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Java's `MalformedBodyRoutesTest.aLicencePolicyWithNulls`: a `null` list, a `null` entry and a blank one are no
    /// entry, the others trimmed and in capitals — the body Java stores, which was refused as malformed.
    #[test]
    fn a_policy_body_with_nulls_is_the_policy_java_stores() {
        let body = r#"{"disallowedCategories":["FORBIDDEN"],"explicitlyAllowedLicenses":[" mit ",null,""],"explicitlyDisallowedLicenses":null}"#;
        let policy: LicensePolicy = serde_json::from_str(body).unwrap();
        assert_eq!(policy.disallowed_categories, BTreeSet::from([LicenseRiskCategory::Forbidden]));
        assert_eq!(policy.explicitly_allowed_licenses, BTreeSet::from(["MIT".to_owned()]));
        assert!(policy.explicitly_disallowed_licenses.is_empty());
        let empty: LicensePolicy = serde_json::from_str("{}").unwrap();
        assert!(empty.disallowed_categories.is_empty() && empty.explicitly_allowed_licenses.is_empty());
    }

    /// And a `null` category is refused, as Jackson refuses it into Java's `EnumSet`.
    #[test]
    fn a_null_category_is_refused() {
        assert!(serde_json::from_str::<LicensePolicy>(r#"{"disallowedCategories":[null]}"#).is_err());
    }

    /// The name a sentence prints is the wire's, `STRONG_COPYLEFT` — Java's `enum.toString()`.
    #[test]
    fn a_category_is_printed_by_its_wire_name() {
        assert_eq!(LicenseRiskCategory::StrongCopyleft.to_string(), "STRONG_COPYLEFT");
        assert_eq!(format!("({})", LicenseRiskCategory::WeakCopyleft), "(WEAK_COPYLEFT)");
    }
}
