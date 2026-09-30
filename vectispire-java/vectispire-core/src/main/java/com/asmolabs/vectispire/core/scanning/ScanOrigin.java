package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import java.time.Instant;

/**
 * A scan's identifier and the two facts about it that nothing writes again once it is created: the
 * target it was of — exactly one of the two ids — and the instant it was created.
 *
 * <p>What a module keeping rows per scan copies, rather than joining {@code scanning}'s table to read
 * them back: the component inventory's rows carry it (V61), and a copy of a fact that never moves
 * cannot come to disagree with its scan.
 */
public record ScanOrigin(long id, Long repoId, Long containerId, Instant createdAt) {

    public static ScanOrigin of(ScanEntity scan) {
        return new ScanOrigin(scan.getId(), scan.getRepoId(), scan.getContainerId(), scan.getCreatedAt());
    }

    public static ScanOrigin of(ScanView scan) {
        return new ScanOrigin(scan.id(), scan.repoId(), scan.containerId(), scan.createdAt());
    }
}
