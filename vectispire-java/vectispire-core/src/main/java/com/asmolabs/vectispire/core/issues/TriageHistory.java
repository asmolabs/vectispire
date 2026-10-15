package com.asmolabs.vectispire.core.issues;

import io.swagger.v3.oas.annotations.media.Schema;
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
            @Schema(types = {"string", "null"}, description = "Null on a finding that is not about a package.")
                    String packageName,
            @Schema(types = {"string", "null"}, description = "Null on a finding that is not about a package.")
                    String packageVersion,
            @Schema(types = {"string", "null"}, description = "Null on a finding about a package, and when the report locates none.")
                    String filePath,
            String state,
            String triageStatus,
            Instant firstSeenAt,
            @Schema(types = {"string", "null"}, format = "date-time", description = "Null while the issue is open.")
                    Instant resolvedAt,
            List<Decision> decisions) {}

    /**
     * One entry of an issue's triage history: a decision, or a fact about the issue that changed what
     * its triage says.
     *
     * @param actor null when nobody decided — see {@code origin}
     * @param origin one of {@code TriageOrigin}: {@code manual}, {@code approval} and {@code review} are
     *     somebody's; {@code expiry} is a deadline that passed, and {@code reopen} a scan or an import that
     *     found a resolved issue again. A report showing the last two as decisions would credit a person
     *     with a lapse or a regression
     * @param scanId the target's last scan at that moment; on a reopening, the scan that saw the issue
     *     again, null for an import
     * @param previousResolvedAt on a reopening only: when the resolution it ended began. Null on every
     *     other entry
     */
    public record Decision(
            String fromStatus,
            String toStatus,
            @Schema(types = {"string", "null"}, description = "Null unless the decision states one; always null on an expiry or a reopening.")
                    String justification,
            @Schema(types = {"string", "null"}, description = "Null unless the decision carries one.")
                    String comment,
            @Schema(types = {"string", "null"}, description = "Null when nobody decided: an expiry or a reopening (see origin).")
                    String actor,
            String origin,
            Instant occurredAt,
            @Schema(types = {"string", "null"}, format = "date-time", description = "Null unless the decision was given a date to be reviewed by.")
                    Instant expiresAt,
            @Schema(types = {"integer", "null"}, format = "int64", description = "Null when the target had no scan, on a reopening an import caused, and once that scan is deleted.")
                    Long scanId,
            @Schema(types = {"string", "null"}, description = "The project version that scan read. Null when it read none, and always on an issue's detail, which does not resolve it.")
                    String version,
            @Schema(types = {"string", "null"}, format = "date-time", description = "On a reopening only: when the resolution it ended began. Null on every other entry.")
                    Instant previousResolvedAt) {}

    /** A whole dossier: one target, its scans, and what was decided. */
    public record Dossier(Repository repository, List<Scan> scans, Instant generatedAt) {}
}
