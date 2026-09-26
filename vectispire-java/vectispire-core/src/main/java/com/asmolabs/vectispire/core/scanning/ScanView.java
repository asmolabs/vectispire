package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import java.time.Instant;

/**
 * A scan as the layers above the services hold it: the row's properties under their own names, not
 * the row.
 *
 * <p>The SBOM and the CVE list travel with it because the scan's own routes serve them; the
 * strings are shared with the row that was read, not copied.
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
        int attempts) {

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
                scan.getAttempts());
    }
}
