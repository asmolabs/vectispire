package com.asmolabs.vectispire.common.domain.compliance;

import java.util.List;

/**
 * Security and regulatory frameworks evaluated by Vectispire.
 */
public enum ComplianceFramework {
    NIS_2(
            "NIS 2 Directive",
            "EU 2022/2555 — Cybersecurity Risk-Management & Supply Chain Security",
            List.of(
                    new ComplianceControl(
                            "NIS2-ART21-VULN",
                            "Vulnerability Handling & Remediation",
                            "All known vulnerabilities must be tracked with strict SLAs and zero unmitigated critical CVEs.",
                            ComplianceControl.Category.VULNERABILITY_MANAGEMENT),
                    new ComplianceControl(
                            "NIS2-ART21-SUPPLY",
                            "Supply Chain Security & Software Bill of Materials",
                            "Every software component and container image must maintain an active SBOM (Software Bill of Materials).",
                            ComplianceControl.Category.SUPPLY_CHAIN),
                    new ComplianceControl(
                            "NIS2-ART21-CRYPTO",
                            "Cryptography & Secrets Management",
                            "No plaintext credentials or hardcoded cryptographic keys in source code repositories.",
                            ComplianceControl.Category.SECRETS_MANAGEMENT),
                    new ComplianceControl(
                            "NIS2-ART21-GOV",
                            "Security Governance & Gate Enforcement",
                            "Deployment gates must enforce blocking security policies across all release artifacts.",
                            ComplianceControl.Category.GOVERNANCE))),

    DORA(
            "DORA",
            "EU 2022/2554 — Digital Operational Resilience Act for Financial Entities",
            List.of(
                    new ComplianceControl(
                            "DORA-ART09-ICT",
                            "ICT Risk Management & Continuous Testing",
                            "Continuous automated vulnerability assessment must be conducted on all digital assets.",
                            ComplianceControl.Category.VULNERABILITY_MANAGEMENT),
                    new ComplianceControl(
                            "DORA-ART11-THIRD",
                            "Third-Party ICT Risk & Dependency Governance",
                            "External dependencies must be inventoried and monitored for critical vulnerabilities and end-of-life.",
                            ComplianceControl.Category.SUPPLY_CHAIN),
                    new ComplianceControl(
                            "DORA-ART13-SECRETS",
                            "Access Control & Secret Leakage Prevention",
                            "System authentication tokens and deployment keys must not be exposed in code or build pipelines.",
                            ComplianceControl.Category.SECRETS_MANAGEMENT),
                    new ComplianceControl(
                            "DORA-ART16-INCIDENT",
                            "Audit Trail & Evidence Retention",
                            "Security scans, findings, and triage decisions must maintain an immutable audit trail.",
                            ComplianceControl.Category.AUDIT_AND_LOGGING))),

    ISO_27001(
            "ISO/IEC 27001:2022",
            "Information Security Management Systems — Annex A Controls",
            List.of(
                    new ComplianceControl(
                            "ISO-A.8.8",
                            "Management of Technical Vulnerabilities",
                            "Information about technical vulnerabilities must be obtained in a timely manner and evaluated.",
                            ComplianceControl.Category.VULNERABILITY_MANAGEMENT),
                    new ComplianceControl(
                            "ISO-A.8.28",
                            "Secure Coding Practices",
                            "Secure coding principles must be applied to software development through automated SAST analysis.",
                            ComplianceControl.Category.SECURE_CODING),
                    new ComplianceControl(
                            "ISO-A.8.9",
                            "Configuration & Infrastructure-as-Code Security",
                            "Security configurations in deployment manifests and infrastructure must be continuously validated.",
                            ComplianceControl.Category.INFRASTRUCTURE_AS_CODE),
                    new ComplianceControl(
                            "ISO-A.5.15",
                            "Access Control & Secrets Protection",
                            "Credentials, private keys, and API tokens must be strictly protected and never leaked in code.",
                            ComplianceControl.Category.SECRETS_MANAGEMENT))),

    PCI_DSS(
            "PCI-DSS v4.0",
            "Payment Card Industry Data Security Standard",
            List.of(
                    new ComplianceControl(
                            "PCI-REQ-6.3",
                            "Security in Software Development",
                            "Software development lifecycle must include automated scanning for vulnerabilities and common flaws.",
                            ComplianceControl.Category.SECURE_CODING),
                    new ComplianceControl(
                            "PCI-REQ-6.4",
                            "Public Vulnerability Remediation",
                            "High-risk and critical vulnerabilities must be resolved within established compliance windows.",
                            ComplianceControl.Category.VULNERABILITY_MANAGEMENT),
                    new ComplianceControl(
                            "PCI-REQ-6.5",
                            "Protection against Software Flaws & Secrets",
                            "Custom software must be free of exposed secrets and injection flaws prior to production release.",
                            ComplianceControl.Category.SECRETS_MANAGEMENT),
                    new ComplianceControl(
                            "PCI-REQ-10.2",
                            "Audit Log Implementation",
                            "Automated audit trails must record security-relevant events and access modifications.",
                            ComplianceControl.Category.AUDIT_AND_LOGGING))),

    EU_CRA(
            "Cyber Resilience Act (EU CRA)",
            "EU Cyber Resilience Act — Mandatory Cybersecurity Requirements for Digital Products",
            List.of(
                    new ComplianceControl(
                            "CRA-ART11-NOTIF",
                            "ENISA / CSIRT 24h Exploited Vulnerability Notification",
                            "Actively exploited vulnerabilities (CISA KEV / EPSS > 0.5) must be identified for mandatory 24h reporting.",
                            ComplianceControl.Category.VULNERABILITY_MANAGEMENT),
                    new ComplianceControl(
                            "CRA-ART10-SBOM",
                            "Machine-Readable SBOM Delivery",
                            "All distributed software and container images must provide an active, machine-readable SBOM.",
                            ComplianceControl.Category.SUPPLY_CHAIN),
                    new ComplianceControl(
                            "CRA-ART10-LIFECYCLE",
                            "Security Support & End-of-Life Tracking",
                            "Third-party packages and base images must be monitored for active security support and end-of-life status.",
                            ComplianceControl.Category.SUPPLY_CHAIN),
                    new ComplianceControl(
                            "CRA-ART10-VULN",
                            "Continuous Vulnerability Handling & Security Updates",
                            "Zero unmitigated critical vulnerabilities and automated security patch availability.",
                            ComplianceControl.Category.VULNERABILITY_MANAGEMENT)));

    private final String title;
    private final String description;
    private final List<ComplianceControl> controls;

    ComplianceFramework(String title, String description, List<ComplianceControl> controls) {
        this.title = title;
        this.description = description;
        this.controls = controls;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public List<ComplianceControl> getControls() {
        return controls;
    }
}
