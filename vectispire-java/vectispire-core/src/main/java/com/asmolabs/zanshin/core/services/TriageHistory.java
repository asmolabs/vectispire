package com.asmolabs.zanshin.core.services;

import java.time.Instant;
import java.util.List;

/**
 * The shape of a detection-and-triage trail, independent of who renders it.
 *
 * <p><b>Here rather than on the controller, and the layer rule is the reason.</b> The CSV and PDF
 * renderers are services; a service reading a controller's record would invert the dependency and
 * fail {@code ArchitectureTest}. That rule is doing real work in this case: the same trail is
 * rendered three ways — JSON, CSV, PDF — and hanging its definition off the JSON one would make
 * the two documents follow whatever the screen happened to need.
 */
public final class TriageHistory {

    private TriageHistory() {}

    /**
     * @param version the version of the most recent scan that read one. <b>Carried on the
     *     repository row although it belongs to a scan</b>: it is what somebody scans the list
     *     for, and making them open a dossier to find out which version is current would be a
     *     page they open only to close
     */
    public record Repository(
            Long id,
            String name,
            String url,
            String branch,
            String version,
            String projectType,
            int scanCount,
            Instant lastScanAt,
            long openIssues,
            long decisions) {}

    /**
     * @param version null for a scan that ran before the manifest was read, and for one whose
     *     tree carries no manifest. The two are not distinguished on purpose — neither is a
     *     statement about the project, and inventing a difference would be inventing a fact
     */
    public record Scan(
            Long id,
            String status,
            String branch,
            String version,
            String projectType,
            Instant createdAt,
            Long durationMs,
            int findingsCount,
            int newIssuesCount,
            int resolvedIssuesCount,
            String error,
            List<ObservedIssue> issues) {}

    /**
     * An issue as one scan saw it, with everything ever decided about it.
     *
     * @param state where the issue stands <b>today</b>, not on the day of the scan. The
     *     difference is the point: a resolved issue under an old scan means it was fixed since,
     *     which is exactly what the trail exists to show
     */
    public record ObservedIssue(
            Long id,
            String type,
            String identifier,
            String severity,
            String packageName,
            String packageVersion,
            String filePath,
            String state,
            String triageStatus,
            Instant firstSeenAt,
            Instant resolvedAt,
            List<Decision> decisions) {}

    /**
     * @param actor null when nobody decided — see {@code origin}
     * @param origin {@code manual} or {@code expiry}: whether somebody decided, or a deadline
     *     passed. A report showing both as decisions would credit a person with a lapse
     */
    public record Decision(
            String fromStatus,
            String toStatus,
            String justification,
            String comment,
            String actor,
            String origin,
            Instant occurredAt,
            Instant expiresAt,
            Long scanId,
            String version) {}

    /** A whole dossier: one target, its scans, and what was decided. */
    public record Dossier(Repository repository, List<Scan> scans, Instant generatedAt) {}
}
