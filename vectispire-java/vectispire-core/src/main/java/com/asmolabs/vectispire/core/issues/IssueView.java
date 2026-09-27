package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

/**
 * An issue as it crosses the API: the row's fields, and none of the row.
 *
 * <p><b>Why a record restating the entity.</b> Routes used to return {@link IssueEntity} itself,
 * which made the table the contract: a column added for the pipeline's own bookkeeping was
 * published the moment it was mapped, and a lazy association added later would have been
 * serialized — or thrown — outside any transaction. The cost is a second list of fields, and the
 * drift that list invites is what {@code EntityViewsTest} is for: it fails when a getter on the
 * entity has no component here, so a new column is a decision rather than an accident.
 *
 * <p>Component names are the entity's property names, so the wire is unchanged: {@code isKev} and
 * {@code isDirectDependency} included.
 */
public record IssueView(
        Long id,
        Long repoId,
        Long containerId,
        String fingerprint,
        String type,
        String identifier,
        String packageName,
        String packageVersion,
        String purl,
        String filePath,
        String owaspCategory,
        String source,
        String tool,
        String toolName,
        String toolVersion,
        String importSource,
        String severity,
        Double epssScore,
        boolean isKev,
        Double cvssScore,
        String cvssVector,
        String fixState,
        String fixVersions,
        String link,
        String description,
        String state,
        Instant firstSeenAt,
        Instant lastSeenAt,
        Instant resolvedAt,
        Long resolutionSeconds,
        Long firstSeenScanId,
        Long lastSeenScanId,
        int timesSeen,
        String triageStatus,
        String triageJustification,
        String triageComment,
        String triagedBy,
        Instant triagedAt,
        Instant triageExpiresAt,
        Boolean isDirectDependency,
        Integer line,
        String ticketRef,
        String ticketAttachedBy,
        String ticketUrl,
        // **Published, not computed.** Nothing writes the columns behind these two since the
        // reachability analyser went; every row reads UNKNOWN and null. They stay because an
        // integration key reads this shape, and a field that vanishes breaks a client silently
        // where a documented dead one does not.
        @Schema(
                description = "Not computed: always UNKNOWN. No analysis establishes whether the code calls the "
                        + "vulnerable component; kept in the response so integrations reading it do not break, "
                        + "and reserved for a real analysis.",
                deprecated = true)
        String reachability,
        @Schema(
                description = "Not computed: always null. Reserved, like reachability, for a real call-graph analysis.",
                deprecated = true)
        String reachableSymbols) {

    public static IssueView of(IssueEntity issue) {
        return new IssueView(
                issue.getId(),
                issue.getRepoId(),
                issue.getContainerId(),
                issue.getFingerprint(),
                issue.getType(),
                issue.getIdentifier(),
                issue.getPackageName(),
                issue.getPackageVersion(),
                issue.getPurl(),
                issue.getFilePath(),
                issue.getOwaspCategory(),
                issue.getSource(),
                issue.getTool(),
                issue.getToolName(),
                issue.getToolVersion(),
                issue.getImportSource(),
                issue.getSeverity(),
                issue.getEpssScore(),
                issue.getIsKev(),
                issue.getCvssScore(),
                issue.getCvssVector(),
                issue.getFixState(),
                issue.getFixVersions(),
                issue.getLink(),
                issue.getDescription(),
                issue.getState(),
                issue.getFirstSeenAt(),
                issue.getLastSeenAt(),
                issue.getResolvedAt(),
                issue.getResolutionSeconds(),
                issue.getFirstSeenScanId(),
                issue.getLastSeenScanId(),
                issue.getTimesSeen(),
                issue.getTriageStatus(),
                issue.getTriageJustification(),
                issue.getTriageComment(),
                issue.getTriagedBy(),
                issue.getTriagedAt(),
                issue.getTriageExpiresAt(),
                issue.getIsDirectDependency(),
                issue.getLine(),
                issue.getTicketRef(),
                issue.getTicketAttachedBy(),
                issue.getTicketUrl(),
                issue.getReachability(),
                issue.getReachableSymbols());
    }
}
