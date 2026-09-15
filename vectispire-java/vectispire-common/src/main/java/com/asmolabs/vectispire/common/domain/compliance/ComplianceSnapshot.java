package com.asmolabs.vectispire.common.domain.compliance;

import java.time.Instant;

/**
 * One framework's verdict, and the state of the estate that produced it.
 *
 * <h2>Stored, not recomputed — and that is the whole design</h2>
 *
 * <p>The backlog curve on the dashboard stores nothing: it reconstructs the past from the
 * {@code firstSeenAt} and {@code resolvedAt} each issue carries. That works because every row
 * transports its own dates.
 *
 * <p><b>A compliance verdict cannot be reconstructed that way.</b> It depends on the backlog of
 * the moment, on the freshness window, on which targets existed, on whether code analysis could
 * reach them, on the declaration of applicability — and on the engine's own code. Recomputing the
 * past therefore means a curve that moves when a threshold is edited, and a verdict from March
 * that nobody can explain in September. Shown to an assessor, that is a progression manufactured
 * by the tool.
 *
 * <p>So each capture carries the verdict <em>and</em> the inputs that produced it. It is the same
 * reason gate verdicts are written to a table rather than derived: what cannot be reproduced must
 * be recorded.
 *
 * @param period the month it stands for, {@code yyyy-MM}. Monthly and not daily: a control that
 *     moves at the pace of scanning produces noise at a finer grain, and a month is the unit an
 *     assessment reads
 * @param targets how many targets the caller's estate held. <b>Carried because the score moves
 *     with it</b>: registering a repository lowers the score, and a curve that punishes watching
 *     more would teach people to watch less
 * @param observed how many had ever been scanned
 * @param fresh how many had been scanned inside the freshness window
 * @param freshnessDays that window, so a verdict can be read back against the rule that produced
 *     it rather than against today's
 * @param controlsDeclared how many of the framework's controls the declaration addressed
 * @param soaFindings what an assessment would have raised on the declaration that month
 */
public record ComplianceSnapshot(
        String period,
        ComplianceFramework framework,
        int score,
        ComplianceControl.Status status,
        int targets,
        int observed,
        int fresh,
        int freshnessDays,
        boolean endOfLifeEnabled,
        boolean codeAnalysisReaches,
        int controlsTotal,
        int controlsDeclared,
        int soaFindings,
        Instant capturedAt) {

    /** The shape of the estate, as one value, so two months can be compared on it. */
    public Shape shape() {
        return new Shape(targets, freshnessDays, endOfLifeEnabled, codeAnalysisReaches);
    }

    /**
     * What a score has to be read against.
     *
     * <p>Two months with the same shape are comparable; two months with different shapes are not,
     * and saying so is more useful than drawing the line anyway.
     */
    public record Shape(int targets, int freshnessDays, boolean endOfLifeEnabled, boolean codeAnalysisReaches) {}
}
