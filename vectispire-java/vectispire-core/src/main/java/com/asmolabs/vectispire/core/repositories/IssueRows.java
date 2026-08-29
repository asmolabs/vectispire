package com.asmolabs.vectispire.core.repositories;

import java.time.Instant;

/**
 * The narrow shapes an issue is read in when the answer needs a few columns and not a row.
 *
 * <p><b>Why these exist.</b> Three HTTP endpoints answered by loading every issue in the estate as
 * a managed {@code IssueEntity} — measured at 23, 223 and 623 entity loads for 20, 220 and 620
 * issues, at a constant query count, so one query returning everything rather than an N+1. Each
 * then read two or three fields off each row and threw the rest away. The need is real: a backlog
 * curve genuinely wants every issue's lifespan, because one resolved inside the window has to be
 * counted as open on the days before. Two timestamps per issue is a small answer; a full entity,
 * with its strings and its persistence context, is not — and at the sizes a real estate reaches it
 * is the difference between a page and a page nobody opens twice.
 *
 * <p><b>Records rather than interface projections</b>, so the column list is visible in one place
 * and a field added to {@code IssueEntity} does not silently widen the query. The component names
 * must match the entity's property names — that is how the projection is derived — which is why
 * {@code firstSeenAt} appears here and the domain record it feeds calls the same value
 * {@code firstSeen}: the mapping is done at the call site, deliberately, rather than by renaming a
 * domain type to suit a query.
 */
public final class IssueRows {

    private IssueRows() {}

    /** Which target an issue belongs to, and nothing else — for the readers that only group. */
    public record Attribution(Long repoId, Long containerId) {}

    /** When an issue appeared and when it stopped being open. What a backlog curve is made of. */
    public record Lifespan(Instant firstSeenAt, Instant resolvedAt) {}

    /** The same, plus the severity a mean-time-to-remediate is grouped by. */
    public record Resolution(String severity, Instant firstSeenAt, Instant resolvedAt) {}

    /**
     * Everything the quality gate weighs, and nothing else.
     *
     * <p>Wider than the others because the gate genuinely reads ten fields per issue — but still a
     * projection, because it reads exactly these ten and never the description, the CVSS vector or
     * the reachability payload that travel with a row. {@code repoId} and {@code containerId} are
     * here to attribute the issue to a target, not to be reported.
     */
    public record GateRow(
            Long id,
            Long repoId,
            Long containerId,
            String state,
            String type,
            String severity,
            String identifier,
            String packageName,
            String fixVersions,
            Boolean isKev,
            String triageStatus) {}

    /** What a posture trend plots: which target, how bad, and over which window. */
    public record Observation(
            Long repoId, Long containerId, String severity, Instant firstSeenAt, Instant resolvedAt) {}
}
