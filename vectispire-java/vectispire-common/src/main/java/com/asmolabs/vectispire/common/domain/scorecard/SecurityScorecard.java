package com.asmolabs.vectispire.common.domain.scorecard;

import java.util.List;

/**
 * Detailed security scorecard evaluation of a target or organization.
 *
 * @param score {@code null} when {@code grade} is {@link SecurityGrade#NO_DATA}: a number would read as
 *     a measurement, and a hundred — what the formula gives when it finds nothing — is the one it
 *     gave for a scope nobody had scanned. Otherwise 0 to 100, at most the observed share of the
 *     scope's targets when not all of them were observed
 * @param totalTargets the targets the card is about, as the caller sees them — one for a target's own
 * @param observedTargets how many of them hold a completed scan: zero is {@code NO_DATA}, fewer than
 *     {@code totalTargets} caps the score
 */
public record SecurityScorecard(
        Long targetId,
        String targetKind,
        String targetName,
        Integer score,
        SecurityGrade grade,
        int totalTargets,
        int observedTargets,
        long openCriticalCount,
        long openHighCount,
        long openKevCount,
        long overdueCount,
        long licenseViolationCount,
        boolean hasAttestation,
        List<String> recommendations) {}
