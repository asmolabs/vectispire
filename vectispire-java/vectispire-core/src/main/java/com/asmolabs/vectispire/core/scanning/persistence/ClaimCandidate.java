package com.asmolabs.vectispire.core.scanning.persistence;

import java.time.Instant;

/**
 * A waiting scan as the claim of a restricted agent reads it: which one, of which repository, and
 * where it stands in the claim order — and nothing else, since a page of them is read at every poll.
 *
 * @param repoId null for an image scan, which no exclusion concerns
 */
public record ClaimCandidate(long id, Long repoId, Instant createdAt) {}
