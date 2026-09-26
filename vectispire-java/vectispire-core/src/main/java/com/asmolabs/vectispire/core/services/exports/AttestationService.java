package com.asmolabs.vectispire.core.services.exports;

import com.asmolabs.vectispire.common.domain.attestation.InTotoAttestation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GateVerdicts;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.settings.ProductVersion;
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

    private final Scans scans;
    private final GitRepositories repositories;
    private final Containers containers;
    private final Findings findings;
    private final GateVerdicts verdicts;
    private final String version;

    public AttestationService(
            Scans scans,
            GitRepositories repositories,
            Containers containers,
            Findings findings,
            GateVerdicts verdicts,
            ProductVersion version) {
        this.scans = scans;
        this.repositories = repositories;
        this.containers = containers;
        this.findings = findings;
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
        ScanEntity scan = scans.findById(scanId)
                .orElseThrow(() -> new NoSuchElementException("Scan not found."));

        if (!ScanStatus.COMPLETED.wireName().equals(scan.getStatus())) {
            throw new NotAttestableException("Scan #" + scanId + " did not complete; there is no result to attest.");
        }
        if (scan.getRepoId() == null && scan.getContainerId() == null) {
            throw new NotAttestableException("Scan #" + scanId + " is attached to no target; there is nothing to name.");
        }
        if (scan.getSbom() == null || scan.getSbom().isBlank()) {
            throw new NotAttestableException("Scan #" + scanId + " recorded no SBOM; there is no artefact to name by digest.");
        }

        boolean isRepository = scan.getRepoId() != null;
        String targetKind = isRepository ? "repository" : "container";
        String targetName = targetName(scan);
        String sbomDigest = Digests.sha256Hex(scan.getSbom());

        InTotoAttestation.FindingsSummary summary = new InTotoAttestation.FindingsSummary(
                findings.countByScanIdAndSeverity(scanId, Severity.CRITICAL.wireName()),
                findings.countByScanIdAndSeverity(scanId, Severity.HIGH.wireName()),
                findings.countByScanIdAndSeverity(scanId, Severity.MEDIUM.wireName()),
                findings.countByScanIdAndSeverity(scanId, Severity.LOW.wireName()),
                findings.countByScanIdAndIsKevTrue(scanId),
                findings.countByScanIdAndType(scanId, FindingType.SECRET.wireName()),
                scan.getFindingsCount());

        return InTotoAttestation.create(
                targetName + "/sbom-scan-" + scanId + ".json",
                sbomDigest,
                version,
                scan.getId(),
                targetKind,
                targetName,
                scan.getBranch(),
                // Not recorded by the scan. Null says so; anything else would be a guess.
                null,
                scan.getCreatedAt(),
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
    private Optional<GateVerdictEntity> verdictAfter(ScanEntity scan) {
        Instant from = scan.getCreatedAt();
        String completed = ScanStatus.COMPLETED.wireName();
        // An empty window with a later scan means "not asked", and must not fall through to the
        // unbounded query — that would hand this scan a verdict about the next one's backlog.
        if (scan.getRepoId() != null) {
            Long id = scan.getRepoId();
            Optional<ScanEntity> next =
                    scans.findFirstByRepoIdAndStatusAndCreatedAtGreaterThanOrderByCreatedAtAsc(id, completed, from);
            return next.isPresent()
                    ? verdicts.findFirstByRepoIdAndDecidedAtGreaterThanEqualAndDecidedAtLessThanOrderByDecidedAtDesc(
                            id, from, next.get().getCreatedAt())
                    : verdicts.findFirstByRepoIdAndDecidedAtGreaterThanEqualOrderByDecidedAtDesc(id, from);
        }
        Long id = scan.getContainerId();
        Optional<ScanEntity> next =
                scans.findFirstByContainerIdAndStatusAndCreatedAtGreaterThanOrderByCreatedAtAsc(id, completed, from);
        return next.isPresent()
                ? verdicts.findFirstByContainerIdAndDecidedAtGreaterThanEqualAndDecidedAtLessThanOrderByDecidedAtDesc(
                        id, from, next.get().getCreatedAt())
                : verdicts.findFirstByContainerIdAndDecidedAtGreaterThanEqualOrderByDecidedAtDesc(id, from);
    }

    private static InTotoAttestation.PolicyAssessment assessment(GateVerdictEntity verdict) {
        List<String> violations = verdict.getViolations() > 0
                ? List.of(verdict.getViolations() + " issue(s) over the policy out of " + verdict.getEvaluated() + " evaluated")
                : List.of();
        return new InTotoAttestation.PolicyAssessment(
                verdict.isPassed(),
                violations,
                verdict.getPolicySource(),
                verdict.getPolicyVersion(),
                verdict.getDecidedAt());
    }

    /** A container by image and tag, as every other screen names it — not "Target #12". */
    private String targetName(ScanEntity scan) {
        if (scan.getRepoId() != null) {
            return repositories.findById(scan.getRepoId())
                    .map(RepositoryEntity::getName)
                    .orElse("repository-" + scan.getRepoId());
        }
        return containers.findById(scan.getContainerId())
                .map(AttestationService::imageOf)
                .orElse("container-" + scan.getContainerId());
    }

    private static String imageOf(ContainerEntity container) {
        return container.getTag() == null ? container.getImageName() : container.getImageName() + ":" + container.getTag();
    }
}
