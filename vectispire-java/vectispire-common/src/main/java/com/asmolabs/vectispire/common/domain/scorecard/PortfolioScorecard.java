package com.asmolabs.vectispire.common.domain.scorecard;

import java.util.List;

/**
 * The estate a reader sees, <b>with no grade of its own</b> (decision 0036): how many targets read
 * each grade, the weakest of them, and the risk points of everything open.
 *
 * <p><b>Why no single grade.</b> Over the summed backlog an estate of a few hundred reasonable
 * targets reads F whatever it fixes — the score falls with every issue added, and an estate adds
 * them by holding more targets; by the weakest link it is the worst target's grade under another
 * name. Neither tells a reader what to act on. How many targets are in F, whether that number falls,
 * and which one first, does. This card carried a {@code score} and a {@code grade} until 0.11.0; they
 * are absent rather than kept with a meaning they no longer have.
 *
 * @param totalTargets the repositories and images the caller sees
 * @param observedTargets those holding a completed scan; the rest are the {@code NO_DATA} row
 * @param grades every grade, {@code NO_DATA} included, in the scale's order — a row of zero stays, so
 *     the distribution always has the same shape; the counts sum to {@code totalTargets}
 * @param weakestTarget the observed target with the lowest score, its risk points breaking a tie;
 *     null when nothing is observed
 * @param riskPoints each open, unsettled issue and each disallowed licence entry of the estate once
 */
public record PortfolioScorecard(
        int totalTargets,
        int observedTargets,
        List<GradeCount> grades,
        SecurityScorecard.WeakestTarget weakestTarget,
        double riskPoints,
        long openCriticalCount,
        long openHighCount,
        long openKevCount,
        long overdueCount,
        long licenseViolationCount) {

    /** How many of the caller's targets read this grade. */
    public record GradeCount(SecurityGrade grade, long targets) {}
}
