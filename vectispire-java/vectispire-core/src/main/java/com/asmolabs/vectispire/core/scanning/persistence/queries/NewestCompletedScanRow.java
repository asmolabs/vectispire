package com.asmolabs.vectispire.core.scanning.persistence.queries;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.time.Instant;

/**
 * A target's newest <b>completed</b> scan, with whether it still holds its SBOM — what a project's
 * consolidated inventory reads each of its targets from.
 *
 * <p>The newest completed scan and not the newest completed scan <em>with</em> an SBOM: the first is
 * what the target is now, and an older inventory borrowed in its place would present last month's tree
 * as today's. A target whose newest completed scan holds no SBOM is one whose inventory is unknown, and
 * the reader says so (decision 0007).
 *
 * <p>Top-level for the reason {@link LatestScanRow} gives: a JPQL {@code new} cannot name a nested type.
 *
 * @param repositoryId the repository scanned, or null for an image
 * @param containerId the image scanned, or null for a repository
 * @param createdAt when the scan was queued, the instant every other screen dates a scan by
 * @param sbomStored whether the scan still holds its SBOM, asked in the query so that none is loaded to
 *     learn it — the step may have failed, or the payload's retention purged it
 */
public record NewestCompletedScanRow(Long repositoryId, Long containerId, Long scanId, Instant createdAt, boolean sbomStored) {

    public ScanTarget target() {
        return repositoryId != null ? new ScanTarget.Repository(repositoryId) : new ScanTarget.Container(containerId);
    }
}
