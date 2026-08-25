package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import com.asmolabs.vectispire.common.domain.attestation.InTotoAttestation;
import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.common.domain.compliance.EvidenceBundleManifest;
import com.asmolabs.vectispire.common.domain.compliance.EvidenceBundleManifest.EvidenceFileEntry;
import com.asmolabs.vectispire.core.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.AuditLog;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
 * (ISO/IEC 27001 A.8.8, DORA Article 10, NIS 2, SOC 2, and EU CRA).
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
    private final CsafGeneratorService csafService;
    private final CycloneDxGeneratorService cycloneDxService;
    private final LicenseGovernanceService licenseService;
    private final SigningKeyService signingKeyService;
    private final ObjectMapper json;

    public EvidenceVaultService(
            ComplianceService compliance,
            AuditLogService auditService,
            AuditLog auditLogRepo,
            Issues issuesRepo,
            Scans scansRepo,
            AttestationService attestationService,
            VexGeneratorService vexService,
            CsafGeneratorService csafService,
            CycloneDxGeneratorService cycloneDxService,
            LicenseGovernanceService licenseService,
            SigningKeyService signingKeyService) {
        this.compliance = compliance;
        this.auditService = auditService;
        this.auditLogRepo = auditLogRepo;
        this.issuesRepo = issuesRepo;
        this.scansRepo = scansRepo;
        this.attestationService = attestationService;
        this.vexService = vexService;
        this.csafService = csafService;
        this.cycloneDxService = cycloneDxService;
        this.licenseService = licenseService;
        this.signingKeyService = signingKeyService;
        this.json = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .enable(SerializationFeature.INDENT_OUTPUT)
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * The certified bundle, <b>within the caller's allowance</b>.
     *
     * <p><b>This was the most complete leak in the API, because packaging everything is its
     * job.</b> It carried a hard-coded {@code Visibility.everything()} and read every triaged
     * issue and every completed scan, so a restricted reader received the estate's compliance
     * posture, its risk-acceptance register and twenty targets' attestations in one archive.
     *
     * <p>Worse than a visibility leak, it was a <b>privilege bypass</b>: entry {@code
     * 02_immutable_audit_log.jsonl} is the whole audit trail — every action by every account —
     * and {@code /api/v1/audit-log} requires a security lead while this route required only a
     * session. The same data behind two doors with two different locks. The route now carries the
     * stricter of the two, and the allowance narrows what a lead with a scoped credential
     * receives.
     */
    @Transactional(readOnly = true)
    public byte[] generateEvidenceBundle(String username, Visibility allowed) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(baos)) {
            List<EvidenceFileEntry> entries = new ArrayList<>();

            // 0. Public Key (Cosign / Sigstore Verification)
            byte[] pubKeyBytes = signingKeyService.getPublicKeyPem().getBytes(StandardCharsets.UTF_8);
            addZipEntry(zip, entries, "00_vectispire_public_key.pub",
                    "Vectispire ECDSA P-256 public key for verifying Cosign signatures and DSSE envelopes",
                    pubKeyBytes);

            // 1. Compliance Frameworks evaluation
            byte[] complianceBytes = json.writeValueAsBytes(compliance.getSummary(allowed));
            addZipEntry(zip, entries, "01_compliance_frameworks.json",
                    "Continuous compliance assessments for NIS 2, DORA, ISO 27001, PCI-DSS, and EU CRA",
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
            // Scoped in SQL rather than filtered afterwards: the register is the triage
            // decisions somebody may see, and reading the rest to discard it was both the leak
            // and the whole-table read.
            List<IssueEntity> triagedIssues = issuesRepo
                    .findAll(new IssueFilters(
                                    null, null, null, null, null, null, false, false, null, allowed)
                            .toSpecification())
                    .stream()
                    .filter(i -> i.getTriageStatus() != null && !i.getTriageStatus().equals("untriaged"))
                    .toList();
            byte[] triageBytes = json.writeValueAsBytes(triagedIssues);
            addZipEntry(zip, entries, "03_triage_and_exemptions.json",
                    "Security triage, risk acceptance overrides, and false-positive justifications",
                    triageBytes);

            // 4. In-toto Supply Chain Attestations & DSSE Envelopes
            List<ScanEntity> completedScans = scansRepo.findAll().stream()
                    .filter(s -> "completed".equalsIgnoreCase(s.getStatus()))
                    // An attestation names its target's provenance and gate verdict, so the
                    // twenty that go into the archive must be twenty the caller may see.
                    .filter(s -> allowed.permits(targetOf(s)))
                    .limit(20)
                    .toList();
            for (ScanEntity scan : completedScans) {
                try {
                    InTotoAttestation attestation = attestationService.generateAttestation(scan.getId());
                    byte[] attestationBytes = json.writeValueAsBytes(attestation);
                    addZipEntry(zip, entries, "04_attestations/scan_" + scan.getId() + "_in_toto.json",
                            "in-toto v0.1 supply chain provenance and gate verdict for scan " + scan.getId(),
                            attestationBytes);

                    // Signed DSSE Envelope
                    DsseEnvelope dsse = signingKeyService.wrapAndSignDsse(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, attestationBytes);
                    byte[] dsseBytes = json.writeValueAsBytes(dsse);
                    addZipEntry(zip, entries, "04_attestations/scan_" + scan.getId() + "_in_toto.dsse.json",
                            "Signed DSSE envelope (RFC 9615) for scan " + scan.getId(),
                            dsseBytes);
                } catch (Exception ignored) {}
            }

            // 5. OpenVEX v0.2.0 document & detached signature
            byte[] vexBytes = json.writeValueAsBytes(vexService.generateAggregate(allowed));
            addZipEntry(zip, entries, "05_openvex_advisory.json",
                    "OpenVEX v0.2.0 Vulnerability Exploitability eXchange document (CRA / EO 14028)",
                    vexBytes);
            addZipEntry(zip, entries, "05_openvex_advisory.json.sig",
                    "Cosign detached ECDSA signature for OpenVEX advisory",
                    signingKeyService.sign(vexBytes).getBytes(StandardCharsets.UTF_8));

            // 6. OASIS CSAF 2.0 VEX Advisory & detached signature
            byte[] csafBytes = json.writeValueAsBytes(csafService.generateAggregate(allowed));
            addZipEntry(zip, entries, "06_csaf_2_0_vex.json",
                    "OASIS CSAF 2.0 Common Security Advisory Framework VEX document (ANSSI / BSI / CISA)",
                    csafBytes);
            addZipEntry(zip, entries, "06_csaf_2_0_vex.json.sig",
                    "Cosign detached ECDSA signature for CSAF 2.0 advisory",
                    signingKeyService.sign(csafBytes).getBytes(StandardCharsets.UTF_8));

            // 7. Open Source License Governance & Copyleft Compliance
            byte[] licenseBytes = json.writeValueAsBytes(licenseService.getSummary());
            addZipEntry(zip, entries, "07_license_compliance.json",
                    "Open Source License Inventory, Copyleft Risk Analysis, and Governance Policy",
                    licenseBytes);

            // 8. CycloneDX 1.5 BOM-Linked VEX Advisory & detached signature
            byte[] cdxBytes = json.writeValueAsBytes(cycloneDxService.generateAggregate(allowed));
            addZipEntry(zip, entries, "08_cyclonedx_1_5_vex.json",
                    "CycloneDX 1.5 Software Bill of Materials with BOM-Linked VEX analysis (OWASP)",
                    cdxBytes);
            addZipEntry(zip, entries, "08_cyclonedx_1_5_vex.json.sig",
                    "Cosign detached ECDSA signature for CycloneDX 1.5 SBOM/VEX",
                    signingKeyService.sign(cdxBytes).getBytes(StandardCharsets.UTF_8));

            // 9. Verification & Manifest
            AuditChain.Verification verification = auditService.verify();
            String chainStatus = verification.broken() == null ? "VERIFIED_INTACT" : "CHAIN_INTEGRITY_COMPROMISED";

            EvidenceBundleManifest manifest = new EvidenceBundleManifest(
                    "1.0",
                    Instant.now(),
                    username != null ? username : "ciso@vectispire.internal",
                    chainStatus,
                    logEntries.size(),
                    entries);

            byte[] manifestBytes = json.writeValueAsBytes(manifest);
            ZipEntry manifestEntry = new ZipEntry("manifest.json");
            zip.putNextEntry(manifestEntry);
            zip.write(manifestBytes);
            zip.closeEntry();

            // 10. Manifest signature (Cosign detached signature)
            String manifestSig = signingKeyService.sign(manifestBytes);
            ZipEntry sigEntry = new ZipEntry("manifest.json.sig");
            zip.putNextEntry(sigEntry);
            zip.write(manifestSig.getBytes(StandardCharsets.UTF_8));
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

    /** A scan attached to neither target is unclassifiable, and a restriction does not wave it through. */
    private static ScanTarget targetOf(ScanEntity scan) {
        if (scan.getRepoId() != null) {
            return new ScanTarget.Repository(scan.getRepoId());
        }
        return scan.getContainerId() == null ? null : new ScanTarget.Container(scan.getContainerId());
    }

}
