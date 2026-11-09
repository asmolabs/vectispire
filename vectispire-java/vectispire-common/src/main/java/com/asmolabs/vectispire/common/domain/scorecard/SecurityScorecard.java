package com.asmolabs.vectispire.common.domain.scorecard;

import java.util.List;

/**
 * Detailed security scorecard evaluation of a target, a project or a solution.
 *
 * @param score {@code null} when {@code grade} is {@link SecurityGrade#NO_DATA}: a number would read as
 *     a measurement, and a hundred — what the formula gives when it finds nothing — is the one it
 *     gave for a scope nobody had scanned. Otherwise 1 to 100 (decision 0036), at most the observed
 *     share of the scope's targets when not all of them were observed. A project's or a solution's is
 *     its weakest observed target's ({@code weakestTarget})
 * @param riskPoints what is open, weighted ({@link CandidateScore#riskPoints}): each open, unsettled
 *     issue and each disallowed licence entry once, however many of a scope's targets name it. A sum,
 *     never a percentage; it keeps moving where the score is held at one. {@code null} exactly when
 *     the score is
 * @param totalTargets the targets the card is about, as the caller sees them — one for a target's own
 * @param observedTargets how many of them hold a completed scan: zero is {@code NO_DATA}, fewer than
 *     {@code totalTargets} caps the score
 * @param weakestTarget a project's or a solution's: the observed target its score is read from. Null
 *     on a target's own card, and with no data
 */
public record SecurityScorecard(
        Long targetId,
        String targetKind,
        String targetName,
        Integer score,
        SecurityGrade grade,
        Double riskPoints,
        int totalTargets,
        int observedTargets,
        long openCriticalCount,
        long openHighCount,
        long openKevCount,
        long overdueCount,
        long licenseViolationCount,
        boolean hasAttestation,
        WeakestTarget weakestTarget,
        List<String> recommendations) {

    /**
     * The target a scope's or the portfolio's weakest link is — one the caller sees, graded as its own
     * card grades it.
     *
     * @param targetKind {@code repository} or {@code container}
     * @param score its own card's score, before the scope's coverage cap
     * @param riskPoints its own card's
     */
    public record WeakestTarget(
            String targetKind, long targetId, String targetName, int score, SecurityGrade grade, double riskPoints) {}
}
