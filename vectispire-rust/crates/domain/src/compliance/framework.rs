//! The six frameworks Vectispire evaluates and their controls — Java's `ComplianceFramework` and
//! `ComplianceControl`.
//!
//! The ids, names and requirements are copied from the Java enum, not written from the standards: they are what
//! an evidence bundle and an assessor's screen quote, and `reference/compliance/frameworks.json` holds them to it.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::java;

/// A requirement within a framework — `ComplianceControl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct ComplianceControl {
    pub id: &'static str,
    pub name: &'static str,
    pub requirement: &'static str,
    pub category: Category,
}

/// What a control is scored on — `ComplianceControl.Category`. The engine assesses a category the same way in
/// every framework that maps one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Category {
    VulnerabilityManagement,
    SupplyChain,
    SecretsManagement,
    SecureCoding,
    InfrastructureAsCode,
    Governance,
    AuditAndLogging,
}

impl Category {
    /// Java's constant name, as the wire carries it.
    pub fn name(self) -> &'static str {
        match self {
            Category::VulnerabilityManagement => "VULNERABILITY_MANAGEMENT",
            Category::SupplyChain => "SUPPLY_CHAIN",
            Category::SecretsManagement => "SECRETS_MANAGEMENT",
            Category::SecureCoding => "SECURE_CODING",
            Category::InfrastructureAsCode => "INFRASTRUCTURE_AS_CODE",
            Category::Governance => "GOVERNANCE",
            Category::AuditAndLogging => "AUDIT_AND_LOGGING",
        }
    }
}

/// A control's verdict, and a framework's — `ComplianceControl.Status`.
///
/// **Declared best to worst, and the order is read** (`worse_of` in the engine): the derived `Ord` is Java's ordinal.
/// [`Status::NoData`] is last and is no verdict: nothing was observed for the control to rest on (decision 0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Compliant,
    Partial,
    NonCompliant,
    NoData,
}

impl Status {
    /// Whether this is a verdict at all — every status but [`Status::NoData`].
    pub fn measured(self) -> bool {
        self != Status::NoData
    }

    /// Java's constant name, as the wire carries it.
    pub fn name(self) -> &'static str {
        match self {
            Status::Compliant => "COMPLIANT",
            Status::Partial => "PARTIAL",
            Status::NonCompliant => "NON_COMPLIANT",
            Status::NoData => "NO_DATA",
        }
    }
}

/// A framework Vectispire evaluates — `ComplianceFramework`, in its declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ComplianceFramework {
    Nis2,
    Iso27001,
    EuCra,
    Dora,
    PciDss,
    Soc2,
}

/// A path segment naming no framework — `InvalidInputException`, its message Java's word for word.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Unknown framework \"{value}\". Expected one of: NIS_2, ISO_27001, EU_CRA, DORA, PCI_DSS, SOC_2.")]
pub struct UnknownFramework {
    pub value: String,
}

impl ComplianceFramework {
    /// Every framework, in Java's `values()` order — the order `evaluateAll` answers in.
    pub const ALL: [ComplianceFramework; 6] = [
        ComplianceFramework::Nis2,
        ComplianceFramework::Iso27001,
        ComplianceFramework::EuCra,
        ComplianceFramework::Dora,
        ComplianceFramework::PciDss,
        ComplianceFramework::Soc2,
    ];

    /// Java's constant name — the key a declaration, a snapshot and the wire carry.
    pub fn name(self) -> &'static str {
        match self {
            ComplianceFramework::Nis2 => "NIS_2",
            ComplianceFramework::Iso27001 => "ISO_27001",
            ComplianceFramework::EuCra => "EU_CRA",
            ComplianceFramework::Dora => "DORA",
            ComplianceFramework::PciDss => "PCI_DSS",
            ComplianceFramework::Soc2 => "SOC_2",
        }
    }

    /// The constant a stored name spells, exactly — not [`from_identifier`](Self::from_identifier)'s leniency.
    pub fn from_name(name: &str) -> Option<ComplianceFramework> {
        ComplianceFramework::ALL.into_iter().find(|framework| framework.name() == name)
    }

    pub fn title(self) -> &'static str {
        match self {
            ComplianceFramework::Nis2 => "NIS 2 Directive",
            ComplianceFramework::Iso27001 => "ISO/IEC 27001:2022",
            ComplianceFramework::EuCra => "Cyber Resilience Act (EU CRA)",
            ComplianceFramework::Dora => "DORA",
            ComplianceFramework::PciDss => "PCI-DSS v4.0",
            ComplianceFramework::Soc2 => "SOC 2",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            ComplianceFramework::Nis2 => "EU 2022/2555 — Cybersecurity Risk-Management & Supply Chain Security",
            ComplianceFramework::Iso27001 => "Information Security Management Systems — Annex A Controls",
            ComplianceFramework::EuCra => {
                "EU Cyber Resilience Act — Mandatory Cybersecurity Requirements for Digital Products"
            }
            ComplianceFramework::Dora => "EU 2022/2554 — Digital Operational Resilience Act for Financial Entities",
            ComplianceFramework::PciDss => "Payment Card Industry Data Security Standard",
            ComplianceFramework::Soc2 => "AICPA Trust Services Criteria — Security, Availability & Confidentiality",
        }
    }

    pub fn controls(self) -> &'static [ComplianceControl] {
        match self {
            ComplianceFramework::Nis2 => &NIS_2,
            ComplianceFramework::Iso27001 => &ISO_27001,
            ComplianceFramework::EuCra => &EU_CRA,
            ComplianceFramework::Dora => &DORA,
            ComplianceFramework::PciDss => &PCI_DSS,
            ComplianceFramework::Soc2 => &SOC_2,
        }
    }

    /// The framework a path segment names, spelt the way people spell it: `ISO-27001`, `iso_27001` and `NIS2` all
    /// name one — `ComplianceFramework.fromIdentifier`.
    ///
    /// Trimmed as `String.trim` trims (every char up to U+0020, not a no-break space) and upper-cased under the root
    /// locale, so that what the server's locale is cannot decide whether `pci_dss` names a framework.
    pub fn from_identifier(value: &str) -> Result<ComplianceFramework, UnknownFramework> {
        let wanted = squeeze(value);
        ComplianceFramework::ALL
            .into_iter()
            .find(|framework| squeeze(framework.name()) == wanted)
            .ok_or_else(|| UnknownFramework { value: value.to_owned() })
    }
}

/// Separators dropped and capitals kept, so the spellings above compare equal.
fn squeeze(value: &str) -> String {
    java::to_upper_root(java::trim(value)).replace(['-', '_'], "")
}

impl Serialize for ComplianceFramework {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for ComplianceFramework {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        ComplianceFramework::from_name(&name)
            .ok_or_else(|| serde::de::Error::custom(format!("no framework is named {name:?}")))
    }
}

const fn control(
    id: &'static str,
    name: &'static str,
    requirement: &'static str,
    category: Category,
) -> ComplianceControl {
    ComplianceControl { id, name, requirement, category }
}

static NIS_2: [ComplianceControl; 4] = [
    control(
        "NIS2-ART21-VULN",
        "Vulnerability Handling & Remediation",
        "All known vulnerabilities must be tracked with strict SLAs and zero unmitigated critical CVEs.",
        Category::VulnerabilityManagement,
    ),
    control(
        "NIS2-ART21-SUPPLY",
        "Supply Chain Security & Software Bill of Materials",
        "Every software component and container image must maintain an active SBOM (Software Bill of Materials).",
        Category::SupplyChain,
    ),
    control(
        "NIS2-ART21-CRYPTO",
        "Cryptography & Secrets Management",
        "No plaintext credentials or hardcoded cryptographic keys in source code repositories.",
        Category::SecretsManagement,
    ),
    control(
        "NIS2-ART21-GOV",
        "Security Governance & Gate Enforcement",
        "Deployment gates must enforce blocking security policies across all release artifacts.",
        Category::Governance,
    ),
];

static ISO_27001: [ComplianceControl; 4] = [
    control(
        "ISO-A.8.8",
        "Management of Technical Vulnerabilities",
        "Information about technical vulnerabilities must be obtained in a timely manner and evaluated.",
        Category::VulnerabilityManagement,
    ),
    control(
        "ISO-A.8.28",
        "Secure Coding Practices",
        "Secure coding principles must be applied to software development through automated SAST analysis.",
        Category::SecureCoding,
    ),
    control(
        "ISO-A.8.9",
        "Configuration & Infrastructure-as-Code Security",
        "Security configurations in deployment manifests and infrastructure must be continuously validated.",
        Category::InfrastructureAsCode,
    ),
    control(
        "ISO-A.5.15",
        "Access Control & Secrets Protection",
        "Credentials, private keys, and API tokens must be strictly protected and never leaked in code.",
        Category::SecretsManagement,
    ),
];

static EU_CRA: [ComplianceControl; 4] = [
    control(
        "CRA-ART14-NOTIF",
        "Actively Exploited Vulnerabilities — Art. 14(1) (CISA KEV)",
        "Open critical, CISA KEV-listed and overdue vulnerabilities are counted: the starting point of an Article 14 \
         notification, applicable since 11 September 2026. The notification itself is neither made nor tracked here.",
        Category::VulnerabilityManagement,
    ),
    control(
        "CRA-ANNEX1-SBOM",
        "Machine-Readable SBOM — Annex I, Part II (1)",
        "All distributed software and container images must provide an active, machine-readable SBOM.",
        Category::SupplyChain,
    ),
    control(
        "CRA-ART13-LIFECYCLE",
        "Third-Party Components & Support Period — Art. 13(5), 13(8)",
        "Third-party packages and base images must be monitored for active security support and end-of-life status.",
        Category::SupplyChain,
    ),
    control(
        "CRA-ANNEX1-VULN",
        "Vulnerability Handling & Security Updates — Annex I, Part II (2); Art. 13(8)",
        "Zero unmitigated critical vulnerabilities and automated security patch availability.",
        Category::VulnerabilityManagement,
    ),
];

static DORA: [ComplianceControl; 4] = [
    control(
        "DORA-ART09-ICT",
        "ICT Risk Management & Continuous Testing",
        "Continuous automated vulnerability assessment must be conducted on all digital assets.",
        Category::VulnerabilityManagement,
    ),
    control(
        "DORA-ART11-THIRD",
        "Third-Party ICT Risk & Dependency Governance",
        "External dependencies must be inventoried and monitored for critical vulnerabilities and end-of-life.",
        Category::SupplyChain,
    ),
    control(
        "DORA-ART13-SECRETS",
        "Access Control & Secret Leakage Prevention",
        "System authentication tokens and deployment keys must not be exposed in code or build pipelines.",
        Category::SecretsManagement,
    ),
    control(
        "DORA-ART16-INCIDENT",
        "Audit Trail & Evidence Retention",
        "Security scans, findings, and triage decisions must maintain a tamper-evident audit trail.",
        Category::AuditAndLogging,
    ),
];

static PCI_DSS: [ComplianceControl; 4] = [
    control(
        "PCI-REQ-6.3",
        "Security in Software Development",
        "Software development lifecycle must include automated scanning for vulnerabilities and common flaws.",
        Category::SecureCoding,
    ),
    control(
        "PCI-REQ-6.4",
        "Public Vulnerability Remediation",
        "High-risk and critical vulnerabilities must be resolved within established compliance windows.",
        Category::VulnerabilityManagement,
    ),
    control(
        "PCI-REQ-6.5",
        "Protection against Software Flaws & Secrets",
        "Custom software must be free of exposed secrets and injection flaws prior to production release.",
        Category::SecretsManagement,
    ),
    control(
        "PCI-REQ-10.2",
        "Audit Log Implementation",
        "Automated audit trails must record security-relevant events and access modifications.",
        Category::AuditAndLogging,
    ),
];

static SOC_2: [ComplianceControl; 4] = [
    control(
        "SOC2-CC6.8",
        "Preventing Unauthorized Changes & Malicious Code",
        "Software development lifecycle must enforce automated code quality, SAST analysis, and deployment gate \
         policies.",
        Category::SecureCoding,
    ),
    control(
        "SOC2-CC7.1",
        "Vulnerability Assessment & Threat Detection",
        "Continuous vulnerability scanning and remediation must be enforced with zero unmitigated critical CVEs.",
        Category::VulnerabilityManagement,
    ),
    control(
        "SOC2-CC6.6",
        "Logical Access & Secrets Management",
        "Credentials, encryption keys, and authentication tokens must not be exposed in source repositories.",
        Category::SecretsManagement,
    ),
    control(
        "SOC2-CC7.2",
        "Security Incident Monitoring & Audit Logging",
        "A tamper-evident audit trail, verified by its hash chain, must record sign-ins, decisions and configuration \
         changes.",
        Category::AuditAndLogging,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_framework_is_named_whatever_the_separators_and_the_locale() {
        // Java's `ComplianceFrameworkIdentifierTest`: a Turkish default locale upper-cases "i" to a dotted capital,
        // and the root locale's mapping is what both sides apply.
        assert_eq!(ComplianceFramework::from_identifier("pci_dss"), Ok(ComplianceFramework::PciDss));
        assert_eq!(ComplianceFramework::from_identifier("iso-27001"), Ok(ComplianceFramework::Iso27001));
        assert_eq!(ComplianceFramework::from_identifier("NIS2"), Ok(ComplianceFramework::Nis2));
        assert_eq!(ComplianceFramework::from_identifier("eu-cra"), Ok(ComplianceFramework::EuCra));
        let refused = ComplianceFramework::from_identifier("hipaa").map_err(|refused| refused.to_string());
        assert!(refused.is_err_and(|message| message.contains("ISO_27001")));
    }
}
