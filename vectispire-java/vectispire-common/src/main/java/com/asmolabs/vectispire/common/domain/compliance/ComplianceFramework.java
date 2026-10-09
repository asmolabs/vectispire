package com.asmolabs.vectispire.common.domain.compliance;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
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

    // The control codes follow the article numbering of the 2022 proposal (Art. 10 obligations,
    // Art. 11 reporting); Regulation (EU) 2024/2847 as adopted moved them to Art. 13, Annex I Part II
    // and Art. 14. The codes are identifiers stored with every declaration and assessment, so they
    // stay; the titles below cite the adopted text, and they are what a reader is shown.
    EU_CRA(
            "Cyber Resilience Act (EU CRA)",
            "EU Cyber Resilience Act — Mandatory Cybersecurity Requirements for Digital Products",
            List.of(
                    new ComplianceControl(
                            "CRA-ART11-NOTIF",
                            "Actively Exploited Vulnerabilities — Art. 14(1) (CISA KEV)",
                            "Open critical, CISA KEV-listed and overdue vulnerabilities are counted: the starting point "
                                    + "of an Article 14 notification, applicable since 11 September 2026. The notification "
                                    + "itself is neither made nor tracked here.",
                            ComplianceControl.Category.VULNERABILITY_MANAGEMENT),
                    new ComplianceControl(
                            "CRA-ART10-SBOM",
                            "Machine-Readable SBOM — Annex I, Part II (1)",
                            "All distributed software and container images must provide an active, machine-readable SBOM.",
                            ComplianceControl.Category.SUPPLY_CHAIN),
                    new ComplianceControl(
                            "CRA-ART10-LIFECYCLE",
                            "Third-Party Components & Support Period — Art. 13(5), 13(8)",
                            "Third-party packages and base images must be monitored for active security support and end-of-life status.",
                            ComplianceControl.Category.SUPPLY_CHAIN),
                    new ComplianceControl(
                            "CRA-ART10-VULN",
                            "Vulnerability Handling & Security Updates — Annex I, Part II (2); Art. 13(8)",
                            "Zero unmitigated critical vulnerabilities and automated security patch availability.",
                            ComplianceControl.Category.VULNERABILITY_MANAGEMENT))),

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
                            "Security scans, findings, and triage decisions must maintain a tamper-evident audit trail.",
                            ComplianceControl.Category.AUDIT_AND_LOGGING))),

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

    SOC_2(
            "SOC 2",
            "AICPA Trust Services Criteria — Security, Availability & Confidentiality",
            List.of(
                    new ComplianceControl(
                            "SOC2-CC6.8",
                            "Preventing Unauthorized Changes & Malicious Code",
                            "Software development lifecycle must enforce automated code quality, SAST analysis, and deployment gate policies.",
                            ComplianceControl.Category.SECURE_CODING),
                    new ComplianceControl(
                            "SOC2-CC7.1",
                            "Vulnerability Assessment & Threat Detection",
                            "Continuous vulnerability scanning and remediation must be enforced with zero unmitigated critical CVEs.",
                            ComplianceControl.Category.VULNERABILITY_MANAGEMENT),
                    new ComplianceControl(
                            "SOC2-CC6.6",
                            "Logical Access & Secrets Management",
                            "Credentials, encryption keys, and authentication tokens must not be exposed in source repositories.",
                            ComplianceControl.Category.SECRETS_MANAGEMENT),
                    new ComplianceControl(
                            "SOC2-CC7.2",
                            "Security Incident Monitoring & Audit Logging",
                            "A tamper-evident audit trail, verified by its hash chain, must record sign-ins, decisions and configuration changes.",
                            ComplianceControl.Category.AUDIT_AND_LOGGING)));

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

    /**
     * The framework a path segment names, spelt the way people spell it: {@code ISO-27001},
     * {@code iso_27001} and {@code NIS2} all name one.
     *
     * <p>Upper-cased with {@link java.util.Locale#ROOT}: under a Turkish default locale {@code
     * "dora"} becomes {@code "DORA"} but {@code "pci_dss"} keeps a dotted capital I and names
     * nothing — which is how the route that parsed this with a bare {@code toUpperCase()} would have
     * refused a framework depending on the server's locale.
     *
     * @throws InvalidInputException for a value that names no framework, with the list of those
     *     that exist
     */
    public static ComplianceFramework fromIdentifier(String value) {
        String wanted = value == null ? "" : squeeze(value);
        return java.util.Arrays.stream(values())
                .filter(framework -> squeeze(framework.name()).equals(wanted))
                .findFirst()
                .orElseThrow(() -> new InvalidInputException("Unknown framework \"" + value + "\". Expected one of: "
                        + String.join(", ", java.util.Arrays.stream(values()).map(Enum::name).toList()) + "."));
    }

    /** Separators dropped and capitals kept, so the spellings above compare equal. */
    private static String squeeze(String value) {
        return value.trim().toUpperCase(java.util.Locale.ROOT).replace("-", "").replace("_", "");
    }
}
