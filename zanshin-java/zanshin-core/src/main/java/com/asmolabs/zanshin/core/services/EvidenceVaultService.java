package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.common.domain.attestation.InTotoAttestation;
import com.asmolabs.zanshin.common.domain.audit.AuditChain;
import com.asmolabs.zanshin.common.domain.compliance.EvidenceBundleManifest;
import com.asmolabs.zanshin.common.domain.compliance.EvidenceBundleManifest.EvidenceFileEntry;
import com.asmolabs.zanshin.core.persistence.AuditLogEntity;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.AuditLog;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.Scans;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Builds certified, cryptographically-sealed evidence bundles for regulatory compliance audits
 * (ISO/IEC 27001 A.8.8, DORA Article 10, NIS 2, SOC 2).
 */
@Service
public class EvidenceVaultService {

    private final ComplianceService compliance;
    private final AuditLogService auditService;
    private final AuditLog auditLogRepo;
    private final Issues issuesRepo;
    private final Scans scansRepo;
    private final AttestationService attestationService;
    private final VexGeneratorService vexService;
    private final LicenseGovernanceService licenseService;
    private final ObjectMapper json;

    public EvidenceVaultService(
            ComplianceService compliance,
            AuditLogService auditService,
            AuditLog auditLogRepo,
            Issues issuesRepo,
            Scans scansRepo,
            AttestationService attestationService,
            VexGeneratorService vexService,
            LicenseGovernanceService licenseService) {
        this.compliance = compliance;
        this.auditService = auditService;
        this.auditLogRepo = auditLogRepo;
        this.issuesRepo = issuesRepo;
        this.scansRepo = scansRepo;
        this.attestationService = attestationService;
        this.vexService = vexService;
        this.licenseService = licenseService;
        this.json = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .enable(SerializationFeature.INDENT_OUTPUT)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Transactional(readOnly = true)
    public byte[] generateEvidenceBundle(String username) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(baos)) {
            List<EvidenceFileEntry> entries = new ArrayList<>();

            // 1. Compliance Frameworks evaluation
            byte[] complianceBytes = json.writeValueAsBytes(compliance.getSummary(Visibility.everything()));
            addZipEntry(zip, entries, "01_compliance_frameworks.json",
                    "Continuous compliance assessments for NIS 2, DORA, ISO 27001, and PCI-DSS",
                    complianceBytes);

            // 2. Immutable Audit Log
            List<AuditLogEntity> logEntries = auditLogRepo.findAllByOrderByTimestampAscIdAsc();
            StringBuilder auditLogJsonl = new StringBuilder();
            for (AuditLogEntity logEntity : logEntries) {
                auditLogJsonl.append(json.writeValueAsString(logEntity)).append("\n");
            }
            byte[] auditBytes = auditLogJsonl.toString().getBytes(StandardCharsets.UTF_8);
            addZipEntry(zip, entries, "02_immutable_audit_log.jsonl",
                    "Cryptographic HMAC Merkle-like immutable audit trail",
                    auditBytes);

            // 3. Triage & Risk Acceptance Register
            List<IssueEntity> triagedIssues = issuesRepo.findAll().stream()
                    .filter(i -> i.getTriageStatus() != null && !i.getTriageStatus().equals("untriaged"))
                    .toList();
            byte[] triageBytes = json.writeValueAsBytes(triagedIssues);
            addZipEntry(zip, entries, "03_triage_and_exemptions.json",
                    "Security triage, risk acceptance overrides, and false-positive justifications",
                    triageBytes);

            // 4. In-toto Supply Chain Attestations
            List<ScanEntity> completedScans = scansRepo.findAll().stream()
                    .filter(s -> "completed".equalsIgnoreCase(s.getStatus()))
                    .limit(20)
                    .toList();
            for (ScanEntity scan : completedScans) {
                try {
                    InTotoAttestation attestation = attestationService.generateAttestation(scan.getId());
                    byte[] attestationBytes = json.writeValueAsBytes(attestation);
                    addZipEntry(zip, entries, "04_attestations/scan_" + scan.getId() + "_in_toto.json",
                            "in-toto v0.1 supply chain provenance and gate verdict for scan " + scan.getId(),
                            attestationBytes);
                } catch (Exception ignored) {}
            }

            // 5. OpenVEX v0.2.0 Exploitability Advisory
            byte[] vexBytes = json.writeValueAsBytes(vexService.generateAggregate());
            addZipEntry(zip, entries, "05_openvex_advisory.json",
                    "OpenVEX v0.2.0 Vulnerability Exploitability eXchange document (CRA / EO 14028)",
                    vexBytes);

            // 6. Open Source License Governance & Copyleft Compliance
            byte[] licenseBytes = json.writeValueAsBytes(licenseService.getSummary());
            addZipEntry(zip, entries, "06_license_compliance.json",
                    "Open Source License Inventory, Copyleft Risk Analysis, and Governance Policy",
                    licenseBytes);

            // 5. Verification & Manifest
            AuditChain.Verification verification = auditService.verify();
            String chainStatus = verification.broken() == null ? "VERIFIED_INTACT" : "CHAIN_INTEGRITY_COMPROMISED";

            EvidenceBundleManifest manifest = new EvidenceBundleManifest(
                    "1.0",
                    Instant.now(),
                    username != null ? username : "ciso@zanshin.internal",
                    chainStatus,
                    logEntries.size(),
                    entries);

            byte[] manifestBytes = json.writeValueAsBytes(manifest);
            ZipEntry manifestEntry = new ZipEntry("manifest.json");
            zip.putNextEntry(manifestEntry);
            zip.write(manifestBytes);
            zip.closeEntry();
        }

        return baos.toByteArray();
    }

    private void addZipEntry(
            ZipOutputStream zip,
            List<EvidenceFileEntry> entries,
            String path,
            String description,
            byte[] content) throws IOException {

        ZipEntry zipEntry = new ZipEntry(path);
        zip.putNextEntry(zipEntry);
        zip.write(content);
        zip.closeEntry();

        String sha256 = sha256(content);
        entries.add(new EvidenceFileEntry(path, description, content.length, sha256));
    }

    private static String sha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
