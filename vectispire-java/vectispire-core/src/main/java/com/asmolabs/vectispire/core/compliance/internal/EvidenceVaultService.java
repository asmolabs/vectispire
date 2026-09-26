package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import com.asmolabs.vectispire.common.domain.attestation.InTotoAttestation;
import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.common.domain.compliance.EvidenceBundleManifest.EvidenceFileEntry;
import com.asmolabs.vectispire.common.domain.compliance.EvidenceBundleManifest;
import com.asmolabs.vectispire.core.audit.AuditLogQueryService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.compliance.ComplianceHistoryService;
import com.asmolabs.vectispire.core.compliance.ComplianceService;
import com.asmolabs.vectispire.core.compliance.StatementOfApplicabilityService;
import com.asmolabs.vectispire.core.crypto.SigningKeyService;
import com.asmolabs.vectispire.core.exports.AttestationService;
import com.asmolabs.vectispire.core.exports.CsafGeneratorService;
import com.asmolabs.vectispire.core.exports.CycloneDxGeneratorService;
import com.asmolabs.vectispire.core.exports.VexGeneratorService;
import com.asmolabs.vectispire.core.inventory.LicenseGovernanceService;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
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
 *
 * <p><b>Two halves, and the second one was missing for a long time.</b> Sections 00-08 describe
 * what the estate contains: its posture against each framework, its SBOMs, its advisories, its
 * attestations. Sections 09-12 describe whether the controls <em>operated</em> — the gate's
 * answers month by month, what was excepted and by whom, whether deadlines were met at the tail,
 * and what the installed rules were able to look for at all.
 *
 * <p>The distinction is not academic: an assessment tests the operation of a control, and an
 * archive of eight perfect posture documents evidences a state rather than a process. See {@link
 * ProcessEvidenceService}.
 */
@Service
public class EvidenceVaultService {

    private final ComplianceService compliance;
    private final AuditLogService auditService;
    private final AuditLogQueryService auditLogRepo;
    private final IssueCatalog issuesRepo;
    private final ScanCatalog scansRepo;
    private final AttestationService attestationService;
    private final VexGeneratorService vexService;
    private final CsafGeneratorService csafService;
    private final CycloneDxGeneratorService cycloneDxService;
    private final LicenseGovernanceService licenseService;
    private final SigningKeyService signingKeyService;
    private final ProcessEvidenceService processEvidence;
    private final StatementOfApplicabilityService soa;
    private final ComplianceHistoryService complianceHistory;
    private final ObjectMapper json;

    public EvidenceVaultService(
            ComplianceService compliance,
            AuditLogService auditService,
            AuditLogQueryService auditLogRepo,
            IssueCatalog issuesRepo,
            ScanCatalog scansRepo,
            AttestationService attestationService,
            VexGeneratorService vexService,
            CsafGeneratorService csafService,
            CycloneDxGeneratorService cycloneDxService,
            LicenseGovernanceService licenseService,
            SigningKeyService signingKeyService,
            ProcessEvidenceService processEvidence,
            StatementOfApplicabilityService soa,
            ComplianceHistoryService complianceHistory) {
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
        this.processEvidence = processEvidence;
        this.soa = soa;
        this.complianceHistory = complianceHistory;
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

            // 0. Public Key — a convenience, and said to be one. A key carried inside the bundle it
            // verifies proves nothing about the bundle: whoever altered the bundle replaces the key
            // too. The verifier's key has to come from elsewhere — the instance's published key,
            // or a copy pinned before this bundle existed.
            byte[] pubKeyBytes = signingKeyService.getPublicKeyPem().getBytes(StandardCharsets.UTF_8);
            addZipEntry(zip, entries, "00_vectispire_public_key.pub",
                    "Vectispire ECDSA P-256 public key, for convenience only: verify against a key obtained out of "
                            + "band (GET /api/v1/crypto/public-key.pub, or a pinned copy), never the one inside this bundle",
                    pubKeyBytes);

            // 1. Compliance Frameworks evaluation
            byte[] complianceBytes = json.writeValueAsBytes(compliance.getSummary(allowed));
            addZipEntry(zip, entries, "01_compliance_frameworks.json",
                    "Continuous compliance assessments for NIS 2, DORA, ISO 27001, PCI-DSS, and EU CRA",
                    complianceBytes);

            // 2. Immutable Audit Log
            AuditLogQueryService.JsonLines logEntries = auditLogRepo.asJsonLines(json);
            byte[] auditBytes = logEntries.text().getBytes(StandardCharsets.UTF_8);
            addZipEntry(zip, entries, "02_immutable_audit_log.jsonl",
                    "Cryptographic HMAC Merkle-like immutable audit trail",
                    auditBytes);

            // 3. Triage & Risk Acceptance Register
            // Scoped in SQL rather than filtered afterwards: the register is the triage
            // decisions somebody may see, and reading the rest to discard it was both the leak
            // and the whole-table read.
            // Serialized by the backlog, with this bundle's mapper: the file is the rows as Jackson
            // reads them, which a view of them would not be (decision 0029).
            byte[] triageBytes = issuesRepo.triagedAsJson(
                    new IssueFilters(null, null, null, null, null, null, false, false, null, allowed), json);
            addZipEntry(zip, entries, "03_triage_and_exemptions.json",
                    "Security triage, risk acceptance overrides, and false-positive justifications",
                    triageBytes);

            // 4. In-toto Supply Chain Attestations & DSSE Envelopes
            // The twenty most recent the caller may see, as ids: an attestation names its target's
            // provenance and gate verdict, so the twenty must be visible ones. Read from
            // `findAll()` they were also the twenty *oldest*, and every scan came with its SBOM.
            List<Long> completedScans = scansRepo.withStatusNewestFirst("completed").stream()
                    .filter(row -> allowed.permits(row.target()))
                    .limit(20)
                    .map(ScanCatalog.ScanOfTarget::id)
                    .toList();
            // **Refusals are written into the bundle; failures are not swallowed.** This loop ended in
            // `catch (Exception ignored) {}`, so a statement that could not be built or signed left
            // the archive without a trace, and an auditor counted twenty scans in the manifest's
            // intent and nineteen files. A scan that cannot be attested now leaves a note saying why;
            // anything else fails the export, which is what a broken signing path should do.
            for (Long scanId : completedScans) {
                try {
                    InTotoAttestation attestation = attestationService.generateAttestation(scanId);
                    byte[] attestationBytes = json.writeValueAsBytes(attestation);
                    addZipEntry(zip, entries, "04_attestations/scan_" + scanId + "_in_toto.json",
                            "in-toto v0.1 supply chain provenance and gate verdict for scan " + scanId,
                            attestationBytes);

                    // Signed DSSE Envelope
                    DsseEnvelope dsse = signingKeyService.wrapAndSignDsse(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, attestationBytes);
                    byte[] dsseBytes = json.writeValueAsBytes(dsse);
                    addZipEntry(zip, entries, "04_attestations/scan_" + scanId + "_in_toto.dsse.json",
                            "Signed DSSE envelope for scan " + scanId,
                            dsseBytes);
                } catch (AttestationService.NotAttestableException refused) {
                    addZipEntry(zip, entries, "04_attestations/scan_" + scanId + "_not_attested.txt",
                            "Why scan " + scanId + " carries no attestation",
                            refused.getMessage().getBytes(StandardCharsets.UTF_8));
                }
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

            // 9. Gate verdict register — that the barrier ran, and refused
            // These four sections are the process evidence: 01-08 describe what the estate
            // contains, and an assessor who has read them still has no answer to "did your
            // controls operate throughout the period". See ProcessEvidenceService.
            byte[] gateBytes = json.writeValueAsBytes(processEvidence.gate(allowed));
            addZipEntry(zip, entries, "09_gate_verdict_register.json",
                    "Every answer the release gate returned: monthly continuity, totals, and each refusal in full (ISO 27001 clause 9.1)",
                    gateBytes);

            // 10. Exceptions register — what was argued away rather than fixed
            byte[] exceptionBytes = json.writeValueAsBytes(processEvidence.exceptions(allowed));
            addZipEntry(zip, entries, "10_exception_register.json",
                    "Risk acceptances and dismissals with their author, justification, approver and expiry, lapsed ones flagged (ISO 27001 A.5.36, clause 6.1.3)",
                    exceptionBytes);

            // 11. Remediation timeliness — deadlines met, by the tail and not the average
            byte[] timelinessBytes = json.writeValueAsBytes(processEvidence.timeliness(allowed));
            addZipEntry(zip, entries, "11_remediation_timeliness.json",
                    "Time to fix against each deadline: share within target, median, 90th percentile, overdue backlog and oldest open item (ISO 27001 clause 9.1, 10.1)",
                    timelinessBytes);

            // 12. Control coverage — what the analysis was able to find
            byte[] coverageBytes = json.writeValueAsBytes(processEvidence.coverage(allowed));
            addZipEntry(zip, entries, "12_control_coverage.json",
                    "Which languages the installed rules reach, and the freshness window applied to section 01 — what a zero finding count does and does not mean (ISO 27001 A.8.28)",
                    coverageBytes);

            // 13. Declaration of applicability — what was claimed, against what was measured
            // Last of the content sections because it is the one that reads the others: it is
            // section 01's verdicts set against the organisation's own claims, and the lines where
            // the two disagree are what an assessment opens with.
            byte[] soaBytes = json.writeValueAsBytes(soa.statements(allowed));
            addZipEntry(zip, entries, "13_statement_of_applicability.json",
                    "Declaration of applicability per framework, each control reconciled against its measured status (ISO 27001 clause 6.1.3 d)",
                    soaBytes);

            // 14. Compliance progression — whether the management system is getting better
            // Clause 9.3 asks a management review to look at the ISMS over time. Sections 09-13
            // show the controls operating; this one is the only place the archive says whether
            // that operation improved, and it is stored rather than recomputed for the reason
            // spelt out on ComplianceSnapshot.
            byte[] historyBytes = json.writeValueAsBytes(complianceHistory.history());
            addZipEntry(zip, entries, "14_compliance_progression.json",
                    "Each framework's verdict month by month, with the estate that produced it and what plausibly moved it (ISO 27001 clause 9.3)",
                    historyBytes);

            // 15. Verification & Manifest
            AuditChain.Verification verification = auditService.verify();
            String chainStatus = verification.broken() == null ? "VERIFIED_INTACT" : "CHAIN_INTEGRITY_COMPROMISED";

            // 1.1 adds sections 09-12, 1.2 section 13, 1.3 section 14. The version is in the manifest so an archive opened in two
            // years says which generation produced it, rather than looking incomplete.
            EvidenceBundleManifest manifest = new EvidenceBundleManifest(
                    "1.3",
                    Instant.now(),
                    username != null ? username : "ciso@vectispire.internal",
                    chainStatus,
                    logEntries.entries(),
                    entries);

            byte[] manifestBytes = json.writeValueAsBytes(manifest);
            ZipEntry manifestEntry = new ZipEntry("manifest.json");
            zip.putNextEntry(manifestEntry);
            zip.write(manifestBytes);
            zip.closeEntry();

            // 16. Manifest signature (Cosign detached signature)
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

    /**
     * A scan attached to neither target is unclassifiable, and a restriction does not wave it through.
     * Read from a {@code [.., repoId, containerId]} projection row.
     */
}
