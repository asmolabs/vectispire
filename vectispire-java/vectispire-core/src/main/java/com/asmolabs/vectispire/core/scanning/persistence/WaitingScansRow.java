package com.asmolabs.vectispire.core.scanning.persistence;

import java.time.Instant;

/**
 * How many scans of one kind wait, and since when the oldest of them has — as {@link
 * ScanRepository#waitingRepositoryScans} and {@link ScanRepository#waitingContainerScans} select it.
 * Top-level for the reason {@link LastScanInstantRow} gives.
 *
 * @param oldestCreatedAt null when none waits
 */
public record WaitingScansRow(Long count, Instant oldestCreatedAt) {}
