package com.asmolabs.vectispire.common.domain.scorecard;

import java.util.List;

/**
 * Detailed security scorecard evaluation of a target or organization.
 */
public record SecurityScorecard(
        Long targetId,
        String targetKind,
        String targetName,
        int score,
        SecurityGrade grade,
        long openCriticalCount,
        long openHighCount,
        long openKevCount,
        long overdueCount,
        long licenseViolationCount,
        boolean hasAttestation,
        List<String> recommendations) {}
