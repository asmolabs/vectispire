package com.asmolabs.vectispire.core.scanning.persistence;

import java.time.Instant;

/**
 * A repository's newest scan instant, as {@link ScanRepository#findLastScanInstantPerRepository} selects it.
 * Top-level, not nested: Hibernate cannot resolve a nested type from the dotted name of a JPQL {@code new}.
 * Here rather than in {@code queries}: {@code ScanCatalog} answers it as a map, so no other module reads it.
 */
public record LastScanInstantRow(Long repoId, Instant lastScanAt) {}
