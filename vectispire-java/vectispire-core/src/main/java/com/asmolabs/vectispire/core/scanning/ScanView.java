package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * A scan as the layers above the services hold it: the row's properties under their own names, not
 * the row.
 *
 * <p>The SBOM and the CVE list travel with it because the scan's own routes serve them; the
 * strings are shared with the row that was read, not copied.
 *
 * @param examinedTypes the built-in types whose step produced in this scan; empty when nobody recorded
 *     it — every scan from before V49, and one that never ran — which is not the empty set, "recorded,
 *     and no step produced" (see {@link ExaminedTypes})
 * @param detectedLanguages the languages the scan's census found in the tree; empty when no whole
 *     census was recorded, which is not the empty set, "no file named a language" (see {@link
 *     DetectedLanguages})
 */
public record ScanView(
        Long id,
        String branch,
        String subPath,
        String status,
        String sbom,
        String cves,
        String summary,
        Long durationMs,
        int findingsCount,
        int newIssuesCount,
        int resolvedIssuesCount,
        String error,
        Instant createdAt,
        String version,
        String projectType,
        Long repoId,
        Long containerId,
        String requiredAgentLabel,
        String claimedBy,
        Instant claimedAt,
        Instant leaseExpiresAt,
        int attempts,
        Instant notBefore,
        List<PluginOutcome> plugins,
        Optional<Set<FindingType>> examinedTypes,
        Optional<Set<Language>> detectedLanguages) {

    public static ScanView of(ScanEntity scan) {
        return new ScanView(
                scan.getId(),
                scan.getBranch(),
                scan.getSubPath(),
                scan.getStatus(),
                scan.getSbom(),
                scan.getCves(),
                scan.getSummary(),
                scan.getDurationMs(),
                scan.getFindingsCount(),
                scan.getNewIssuesCount(),
                scan.getResolvedIssuesCount(),
                scan.getError(),
                scan.getCreatedAt(),
                scan.getVersion(),
                scan.getProjectType(),
                scan.getRepoId(),
                scan.getContainerId(),
                scan.getRequiredAgentLabel(),
                scan.getClaimedBy(),
                scan.getClaimedAt(),
                scan.getLeaseExpiresAt(),
                scan.getAttempts(),
                scan.getNotBefore(),
                PluginOutcome.read(scan.getPluginSteps()),
                ExaminedTypes.read(scan.getExaminedTypes()),
                DetectedLanguages.read(scan.getDetectedLanguages()));
    }
}
