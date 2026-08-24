package com.asmolabs.vectispire.common.domain.exports;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Builds a SARIF 2.1.0 log for a target's issues.
 *
 * <p>SARIF is permissive enough that a technically valid document can still be useless in a
 * code scanning interface. The decisions that avoid that:
 *
 * <ul>
 *   <li><b>Triaged issues are suppressions, not omissions.</b> Removing them makes the
 *       platform report them as new on the next upload, undoing the triage work; a
 *       suppression instead carries its justification, so the reviewer sees <em>why</em> it is
 *       set aside. {@code NOT_AFFECTED} and {@code FIXED} are suppressed; {@code AFFECTED} is
 *       not — deciding an issue is real has to stay visible.
 *   <li><b>Resolved issues are excluded.</b> They are gone, and SARIF describes the current
 *       state of the branch being built.
 *   <li><b>Every result has a location</b>, falling back to the repository root when a
 *       dependency issue has no file. GitHub silently discards results with no location, so an
 *       honestly-empty location would make the vulnerability findings vanish — that is, most
 *       of them.
 *   <li><b>{@code partialFingerprints} carries Vectispire's fingerprint</b>, which lets the
 *       platform match an issue across uploads even when the file moves and the line shifts.
 * </ul>
 */
public final class SarifExport {

    private SarifExport() {}

    public record Options(String targetName, String toolVersion, String informationUri) {

        public Options(String targetName) {
            this(targetName, "1.0.0", null);
        }
    }

    /**
     * SARIF has four levels and no notion of "critical".
     *
     * <p>Anything a security tool would call critical or high has to land on {@code error},
     * because {@code warning} is what a reviewer scrolls past without reading.
     */
    private static String levelOf(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM, UNKNOWN -> "warning";
            case LOW, NEGLIGIBLE -> "note";
        };
    }

    /**
     * GitHub sorts and filters on this property, <b>not</b> on {@code level}: it is what keeps
     * a critical distinguishable from a high once both are {@code error}. The values follow the
     * CVSS bands GitHub documents.
     *
     * <p>{@link Severity#UNKNOWN} has none, deliberately — inventing a score for an advisory
     * that carries no severity would put a number in front of a reviewer that nobody computed.
     */
    private static String securitySeverityOf(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "9.5";
            case HIGH -> "8.0";
            case MEDIUM -> "5.5";
            case LOW -> "3.0";
            case NEGLIGIBLE -> "1.0";
            case UNKNOWN -> null;
        };
    }

    private static String labelOf(FindingType type) {
        if (type == null) {
            return "Issue";
        }
        return switch (type) {
            case VULNERABILITY -> "Vulnerability";
            case SECRET -> "Exposed secret";
            case IAC -> "Infrastructure configuration";
            case LICENSE -> "License";
            case EOL -> "End of life";
            case AI_REVIEW -> "AI review";
            case SAST -> "Vulnerable code";
            case QUALITY -> "Code quality";
        };
    }

    public static SarifLog build(Collection<ExportableIssue> issues, Options options) {
        // Insertion-ordered: the rules' order defines `ruleIndex`, and a result pointing at
        // the wrong index describes itself with another rule's title.
        Map<String, SarifLog.Rule> rules = new LinkedHashMap<>();
        Map<String, Integer> ruleIndex = new LinkedHashMap<>();
        List<SarifLog.Result> results = new ArrayList<>();

        for (ExportableIssue issue : issues) {
            if (issue.resolved()) {
                continue;
            }
            String ruleId = ruleIdOf(issue);
            ruleIndex.computeIfAbsent(ruleId, id -> rules.size());
            rules.computeIfAbsent(ruleId, id -> rule(issue, id));

            results.add(result(issue, ruleId, ruleIndex.get(ruleId)));
        }

        SarifLog.Driver driver = new SarifLog.Driver(
                "Vectispire",
                options.toolVersion() == null ? "1.0.0" : options.toolVersion(),
                blankToNull(options.informationUri()),
                List.copyOf(rules.values()));

        return new SarifLog(
                SarifLog.SCHEMA,
                SarifLog.VERSION,
                List.of(new SarifLog.Run(
                        new SarifLog.Tool(driver), List.copyOf(results), Map.of("target", options.targetName()))));
    }

    /**
     * Stable, and partitioned by type.
     *
     * <p>A gitleaks rule and a checkov check can collide on an identifier, and a platform
     * indexed on {@code ruleId} would then merge two unrelated classes of issue under one
     * title.
     */
    private static String ruleIdOf(ExportableIssue issue) {
        String type = issue.type() == null ? "unspecified" : issue.type().wireName();
        String identifier = blankToNull(issue.identifier()) == null ? "unspecified" : issue.identifier();
        return "vectispire/" + type + "/" + identifier;
    }

    private static SarifLog.Rule rule(ExportableIssue issue, String ruleId) {
        Map<String, Object> properties = new TreeMap<>();
        properties.put("tags", tagsOf(issue));

        String securitySeverity = securitySeverityOf(issue.severity());
        if (securitySeverity != null) {
            properties.put("security-severity", securitySeverity);
        }

        String identifier = blankToNull(issue.identifier());
        return new SarifLog.Rule(
                ruleId,
                (identifier != null ? identifier : issue.type() == null ? "" : issue.type().wireName()).replace(" ", ""),
                new SarifLog.Text(labelOf(issue.type()) + ": " + (identifier != null ? identifier : "unidentified")),
                blankToNull(issue.description()) == null
                        ? null
                        : new SarifLog.Text(truncate(issue.description(), 1000)),
                blankToNull(issue.link()),
                properties);
    }

    /** {@code security} only for what is genuinely a security finding. */
    private static List<String> tagsOf(ExportableIssue issue) {
        if (issue.type() == null) {
            return List.of("security");
        }
        String category = issue.type() == FindingType.QUALITY ? "quality" : "security";
        return List.of(category, issue.type().wireName());
    }

    private static SarifLog.Result result(ExportableIssue issue, String ruleId, int index) {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("vectispireIssueId", issue.id());
        properties.put("type", issue.type() == null ? null : issue.type().wireName());
        properties.put("firstSeen", issue.firstSeenAt() == null ? "" : Digests.canonical(issue.firstSeenAt()));
        properties.put("timesSeen", issue.timesSeen() == null || issue.timesSeen() == 0 ? 1 : issue.timesSeen());
        if (issue.directness() != com.asmolabs.vectispire.common.domain.dependencies.Directness.UNKNOWN) {
            properties.put("dependency", issue.directness().label());
        }

        return new SarifLog.Result(
                ruleId,
                index,
                levelOf(issue.severity()),
                new SarifLog.Text(message(issue)),
                List.of(location(issue)),
                issue.fingerprint() == null ? Map.of() : Map.of("vectispireIssueFingerprint", issue.fingerprint()),
                properties,
                isSuppressed(issue) ? List.of(new SarifLog.Suppression("external", suppressionJustification(issue))) : null);
    }

    /**
     * What the developer reads in the merge request, hence what tells them what to do.
     *
     * <p>The fixed version is the most useful thing to put in front of someone who has thirty
     * seconds: it turns "there is a CVE" into "change this line".
     */
    private static String message(ExportableIssue issue) {
        List<String> parts = new ArrayList<>();
        if (blankToNull(issue.packageName()) != null) {
            parts.add(blankToNull(issue.packageVersion()) != null
                    ? issue.packageName() + " " + issue.packageVersion()
                    : issue.packageName());
        }
        String identifier = blankToNull(issue.identifier());
        parts.add(identifier != null ? identifier : labelOf(issue.type()));

        StringBuilder message = new StringBuilder(String.join(" — ", parts));
        if (issue.hasFixVersions()) {
            message.append(" — fixed in ").append(issue.fixVersions());
        } else if (issue.fixState() == ExportableIssue.FixState.NOT_FIXED) {
            message.append(" — no published fix");
        }
        if (issue.kev()) {
            message.append(" — known active exploitation (CISA KEV)");
        }
        if (issue.directness() == com.asmolabs.vectispire.common.domain.dependencies.Directness.TRANSITIVE) {
            message.append(" — transitive dependency");
        }
        return message.toString();
    }

    private static SarifLog.Location location(ExportableIssue issue) {
        String path = blankToNull(issue.filePath());
        SarifLog.PhysicalLocation physical = new SarifLog.PhysicalLocation(
                // A relative URI, as SARIF requires for source the consumer resolves against
                // the repository it has just checked out.
                new SarifLog.ArtifactLocation(path == null ? "." : path),
                issue.line() == null || issue.line() <= 0 ? null : new SarifLog.Region(issue.line()));

        return new SarifLog.Location(
                physical,
                blankToNull(issue.purl()) == null
                        ? null
                        : List.of(new SarifLog.LogicalLocation(issue.purl(), "package")));
    }

    private static boolean isSuppressed(ExportableIssue issue) {
        // The same question `TriageStatus.isSettled` answers, and the same answer: a decision
        // that took the issue out of the way is what a suppression documents.
        return issue.triageStatus() != null && issue.triageStatus().isSettled();
    }

    private static String suppressionJustification(ExportableIssue issue) {
        List<String> parts = new ArrayList<>();
        parts.add(issue.triageStatus().wireName());
        addIfPresent(parts, issue.triageJustification());
        addIfPresent(parts, issue.triageComment());
        if (blankToNull(issue.triagedBy()) != null) {
            parts.add("decided by " + issue.triagedBy());
        }
        if (issue.triageExpiresAt() != null) {
            parts.add("to review on " + issue.triageExpiresAt().atZone(ZoneOffset.UTC).toLocalDate());
        }
        return String.join(" — ", parts);
    }

    private static void addIfPresent(List<String> parts, String value) {
        if (blankToNull(value) != null) {
            parts.add(value);
        }
    }

    private static String truncate(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
