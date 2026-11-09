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
 *
 * <p><b>Which components the server sends as null is part of the contract.</b> The document said
 * {@code string} of every reference component, and the client generated {@code link?: string} for a
 * field that is {@code null} on every secret and every SAST finding — a type that promised a value
 * or nothing, while the server sent neither. A component whose column allows null, and which some
 * producer leaves null, says so with {@code types = {…, "null"}}; the three whose column allows null
 * and which every producer fills ({@code identifier}, {@code source}, {@code severity}) say why
 * beside them. {@code ResponseNullabilityTest} reads the columns of the running schema and the served
 * document, and fails when the two disagree.
 */
public record IssueView(
        Long id,
        @Schema(types = {"integer", "null"}, format = "int64", description = "The repository the issue was found on; null on a container image's issue.")
                Long repoId,
        @Schema(types = {"integer", "null"}, format = "int64", description = "The container image the issue was found on; null on a repository's issue.")
                Long containerId,
        String fingerprint,
        String type,
        // Never null although the column allows it: every producer names one — the scanners fall
        // back to "unknown", a SARIF result without a rule is refused, a licence or an end of life
        // is its own identifier.
        String identifier,
        @Schema(types = {"string", "null"}, description = "Null on a finding that is not about a package: a secret, a SAST, IaC, plugin or imported finding.")
                String packageName,
        @Schema(types = {"string", "null"}, description = "Null on a finding that is not about a package.")
                String packageVersion,
        @Schema(types = {"string", "null"}, description = "Null on a finding that is not about a package, and when the scanner gave no purl.")
                String purl,
        @Schema(types = {"string", "null"}, description = "Null on a finding about a package (vulnerability, licence, end of life), and when the report locates none.")
                String filePath,
        @Schema(types = {"string", "null"}, description = "Null unless the rule that found the issue declares an OWASP Top 10 category.")
                String owaspCategory,
        // Never null although the column allows it: the scanner's name, the plugin's id, the SARIF
        // driver's name (required by the import) — every producer sets one.
        String source,
        @Schema(types = {"string", "null"}, description = "The key that scopes a plugin or imported issue's resolution (plugin:<id>, import:<source>/<tool>); null for what Vectispire's own scanners found.")
                String tool,
        @Schema(types = {"string", "null"}, description = "The report's driver name; null for what Vectispire's own scanners found.")
                String toolName,
        @Schema(types = {"string", "null"}, description = "The report's driver version; null for what Vectispire's own scanners found, and when the driver states none.")
                String toolVersion,
        @Schema(types = {"string", "null"}, description = "The declared SARIF source's slug; null unless an import reported the issue.")
                String importSource,
        // Never null although the column allows it: every producer grades the finding, and one that
        // carries no grade is read as medium (SARIF, plugins) or unknown (the matcher).
        String severity,
        @Schema(types = {"number", "null"}, format = "double", description = "Null until the threat-intelligence feed scores the CVE, and on findings that are not CVEs.")
                Double epssScore,
        boolean isKev,
        @Schema(types = {"number", "null"}, format = "double", description = "Null when no advisory gave one.")
                Double cvssScore,
        @Schema(types = {"string", "null"}, description = "Null when no advisory gave one.")
                String cvssVector,
        @Schema(types = {"string", "null"}, description = "Null when the scanner says nothing about a fix.")
                String fixState,
        @Schema(types = {"string", "null"}, description = "Null when no fixed version is known.")
                String fixVersions,
        @Schema(types = {"string", "null"}, description = "Null when the scanner gives no reference.")
                String link,
        @Schema(types = {"string", "null"}, description = "Null when neither an advisory nor the scanner supplies a text.")
                String description,
        String state,
        Instant firstSeenAt,
        Instant lastSeenAt,
        @Schema(types = {"string", "null"}, format = "date-time", description = "Null while the issue is open.")
                Instant resolvedAt,
        @Schema(types = {"integer", "null"}, format = "int64", description = "Null while the issue is open.")
                Long resolutionSeconds,
        @Schema(types = {"integer", "null"}, format = "int64", description = "Null on an issue an import created, and once that scan is deleted.")
                Long firstSeenScanId,
        @Schema(types = {"integer", "null"}, format = "int64", description = "Null on an issue an import last reported, and once that scan is deleted.")
                Long lastSeenScanId,
        int timesSeen,
        String triageStatus,
        @Schema(types = {"string", "null"}, description = "Null unless the triage decision states one.")
                String triageJustification,
        @Schema(types = {"string", "null"}, description = "Null unless the triage decision carries one.")
                String triageComment,
        @Schema(types = {"string", "null"}, description = "Null while nobody has decided on the issue.")
                String triagedBy,
        @Schema(types = {"string", "null"}, format = "date-time", description = "Null while nobody has decided on the issue.")
                Instant triagedAt,
        @Schema(types = {"string", "null"}, format = "date-time", description = "Null unless the decision was given a date to be reviewed by.")
                Instant triageExpiresAt,
        // What a decision awaiting approval asked for, so the approver grants that or turns it down:
        // queued, the issue reads only `pending_approval`, and a "Won't Fix" and a clearance looked alike.
        @Schema(
                types = {"string", "null"},
                description = "While triageStatus is pending_approval: the settled status the request asked for "
                        + "(not_affected, will_not_fix or fixed). An approval grants this status or is refused (409, "
                        + "urn:vectispire:problem:triage-approval-differs). Null otherwise, and on requests queued "
                        + "before it was recorded, which the approver grants as they choose.")
                String triageRequestedStatus,
        @Schema(types = {"boolean", "null"}, description = "Null when the scanner cannot tell a direct dependency from a transitive one, which a container image's scan never can, and on findings that are not about a package.")
                Boolean isDirectDependency,
        @Schema(types = {"integer", "null"}, format = "int32", description = "Null on a finding about a package, and when the report locates none.")
                Integer line,
        @Schema(types = {"string", "null"}, description = "Null while no ticket is attached.")
                String ticketRef,
        @Schema(types = {"string", "null"}, description = "Who attached the ticket; null while none is, and when the ticketing integration opened it.")
                String ticketAttachedBy,
        @Schema(types = {"string", "null"}, description = "Null while no ticket is attached, and when its reference was attached without a URL.")
                String ticketUrl) {

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
                issue.getTriageRequestedStatus(),
                issue.getIsDirectDependency(),
                issue.getLine(),
                issue.getTicketRef(),
                issue.getTicketAttachedBy(),
                issue.getTicketUrl());
    }
}
