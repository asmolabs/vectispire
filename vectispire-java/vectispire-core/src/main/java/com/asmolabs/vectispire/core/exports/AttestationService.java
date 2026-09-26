package com.asmolabs.vectispire.core.exports;

import com.asmolabs.vectispire.common.domain.attestation.InTotoAttestation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.gate.GateRegisterService;
import com.asmolabs.vectispire.core.gate.GateVerdictView;
import com.asmolabs.vectispire.core.services.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.services.scanning.ScanView;
import com.asmolabs.vectispire.core.settings.ProductVersion;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * The in-toto statement for one scan, built only from what was recorded.
 *
 * <p><b>What can be attested, and what cannot.</b> A scan stores its SBOM but neither the commit it
 * read nor the image digest it pulled, so the only artefact this statement can name by its own
 * digest is that SBOM. The subject is therefore the SBOM document: "this inventory, produced by this
 * scan, of this target". The earlier version named the target and gave it the SBOM's digest — or,
 * without an SBOM, the hash of the string {@code name:branch}, which is the digest of nothing a
 * consumer could ever hold.
 */
@Service
public class AttestationService {

    private final ScanCatalog scans;
    private final TargetCatalog targets;
    private final GateRegisterService verdicts;
    private final String version;

    public AttestationService(
            ScanCatalog scans,
            TargetCatalog targets,
            GateRegisterService verdicts,
            ProductVersion version) {
        this.scans = scans;
        this.targets = targets;
        this.verdicts = verdicts;
        // The version every export states. It was the literal "0.9.0", which every release after
        // that one would have gone on claiming inside a signed document.
        this.version = version.get();
    }

    /**
     * Refused rather than approximated: the scan did not complete, or left no SBOM to name.
     *
     * <p>A failed scan's statement would report zero findings — a clean result that never
     * happened — and a scan without an SBOM has no subject anybody could verify.
     */
    public static class NotAttestableException extends RuntimeException {
        public NotAttestableException(String message) {
            super(message);
        }
    }

    public InTotoAttestation generateAttestation(long scanId) {
        ScanView scan = scans.scan(scanId)
                .orElseThrow(() -> new NoSuchElementException("Scan not found."));

        if (!ScanStatus.COMPLETED.wireName().equals(scan.status())) {
            throw new NotAttestableException("Scan #" + scanId + " did not complete; there is no result to attest.");
        }
        if (scan.repoId() == null && scan.containerId() == null) {
            throw new NotAttestableException("Scan #" + scanId + " is attached to no target; there is nothing to name.");
        }
        if (scan.sbom() == null || scan.sbom().isBlank()) {
            throw new NotAttestableException("Scan #" + scanId + " recorded no SBOM; there is no artefact to name by digest.");
        }

        boolean isRepository = scan.repoId() != null;
        String targetKind = isRepository ? "repository" : "container";
        String targetName = targetName(scan);
        String sbomDigest = Digests.sha256Hex(scan.sbom());

        InTotoAttestation.FindingsSummary summary = new InTotoAttestation.FindingsSummary(
                scans.countFindings(scanId, Severity.CRITICAL.wireName()),
                scans.countFindings(scanId, Severity.HIGH.wireName()),
                scans.countFindings(scanId, Severity.MEDIUM.wireName()),
                scans.countFindings(scanId, Severity.LOW.wireName()),
                scans.countKevFindings(scanId),
                scans.countFindingsOfType(scanId, FindingType.SECRET.wireName()),
                scan.findingsCount());

        return InTotoAttestation.create(
                targetName + "/sbom-scan-" + scanId + ".json",
                sbomDigest,
                version,
                scan.id(),
                targetKind,
                targetName,
                scan.branch(),
                // Not recorded by the scan. Null says so; anything else would be a guess.
                null,
                scan.createdAt(),
                verdictAfter(scan).map(AttestationService::assessment).orElse(null),
                summary,
                sbomDigest);
    }

    /**
     * The gate verdict that judged the backlog this scan left, if a pipeline asked for one.
     *
     * <p>The gate is evaluated per target, not per scan, and records when it was asked. The verdict
     * belonging to a scan is therefore the last one recorded between it and the target's next
     * completed scan: before, it judged an older backlog; after, a newer one. None in that window
     * means the gate was not consulted, and the statement says nothing rather than "passed".
     */
    private Optional<GateVerdictView> verdictAfter(ScanView scan) {
        Instant from = scan.createdAt();
        String completed = ScanStatus.COMPLETED.wireName();
        // An empty window with a later scan means "not asked", and must not fall through to the
        // unbounded query — that would hand this scan a verdict about the next one's backlog.
        if (scan.repoId() != null) {
            Long id = scan.repoId();
            Optional<ScanView> next = scans.nextWithStatusAfter(new ScanTarget.Repository(id), completed, from);
            return verdicts.lastForRepository(id, from, next.map(ScanView::createdAt).orElse(null));
        }
        Long id = scan.containerId();
        Optional<ScanView> next = scans.nextWithStatusAfter(new ScanTarget.Container(id), completed, from);
        return verdicts.lastForContainer(id, from, next.map(ScanView::createdAt).orElse(null));
    }

    private static InTotoAttestation.PolicyAssessment assessment(GateVerdictView verdict) {
        List<String> violations = verdict.violations() > 0
                ? List.of(verdict.violations() + " issue(s) over the policy out of " + verdict.evaluated() + " evaluated")
                : List.of();
        return new InTotoAttestation.PolicyAssessment(
                verdict.passed(),
                violations,
                verdict.policySource(),
                verdict.policyVersion(),
                verdict.decidedAt());
    }

    /** A container by image and tag, as every other screen names it — not "Target #12". */
    private String targetName(ScanView scan) {
        if (scan.repoId() != null) {
            return targets.repository(scan.repoId())
                    .map(RepositoryView::name)
                    .orElse("repository-" + scan.repoId());
        }
        return targets.container(scan.containerId())
                .map(AttestationService::imageOf)
                .orElse("container-" + scan.containerId());
    }

    private static String imageOf(ContainerView container) {
        return container.tag() == null ? container.imageName() : container.imageName() + ":" + container.tag();
    }
}
