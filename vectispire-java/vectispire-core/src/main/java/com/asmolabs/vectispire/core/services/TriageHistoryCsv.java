package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.core.services.TriageHistory.Decision;
import com.asmolabs.vectispire.core.services.TriageHistory.ObservedIssue;
import com.asmolabs.vectispire.core.services.TriageHistory.Scan;
import java.time.Instant;
import java.util.List;

/**
 * The trail as rows, for a spreadsheet or a compliance tool.
 *
 * <p><b>One row per decision, and one row per observation with no decision.</b> The alternative
 * — a row per issue with the decisions folded into a cell — reads well and cannot be filtered,
 * sorted or counted, which is the only reason somebody asks for CSV. An issue nobody has triaged
 * still gets its line: "detected and never decided upon" is a finding of the audit, not a gap in
 * the export.
 */
public final class TriageHistoryCsv {

    private TriageHistoryCsv() {}

    private static final List<String> HEADER = List.of(
            "repository",
            "repository_url",
            "scan_id",
            "scan_at",
            "scan_status",
            "branch",
            "project_type",
            "version",
            "issue_id",
            "issue_type",
            "identifier",
            "severity",
            "component",
            "location",
            "issue_state",
            "current_triage",
            "first_seen_at",
            "resolved_at",
            "decision_at",
            "decision_from",
            "decision_to",
            "decision_justification",
            "decision_actor",
            "decision_origin",
            "decision_expires_at",
            "decision_comment");

    public static String render(TriageHistory.Repository repository, List<Scan> scans) {
        StringBuilder csv = new StringBuilder();
        csv.append(String.join(",", HEADER)).append('\n');

        for (Scan scan : scans) {
            for (ObservedIssue issue : scan.issues()) {
                if (issue.decisions().isEmpty()) {
                    csv.append(line(repository, scan, issue, null)).append('\n');
                    continue;
                }
                for (Decision decision : issue.decisions()) {
                    csv.append(line(repository, scan, issue, decision)).append('\n');
                }
            }
        }
        return csv.toString();
    }

    private static String line(TriageHistory.Repository repository, Scan scan, ObservedIssue issue, Decision decision) {
        return String.join(
                ",",
                quote(repository.name()),
                quote(repository.url()),
                quote(String.valueOf(scan.id())),
                quote(stamp(scan.createdAt())),
                quote(scan.status()),
                quote(scan.branch()),
                quote(scan.projectType()),
                quote(scan.version()),
                quote(String.valueOf(issue.id())),
                quote(issue.type()),
                quote(issue.identifier()),
                quote(issue.severity()),
                quote(component(issue)),
                quote(issue.filePath()),
                quote(issue.state()),
                quote(issue.triageStatus()),
                quote(stamp(issue.firstSeenAt())),
                quote(stamp(issue.resolvedAt())),
                quote(decision == null ? "" : stamp(decision.occurredAt())),
                quote(decision == null ? "" : decision.fromStatus()),
                quote(decision == null ? "" : decision.toStatus()),
                quote(decision == null ? "" : decision.justification()),
                quote(decision == null ? "" : decision.actor()),
                quote(decision == null ? "" : decision.origin()),
                quote(decision == null ? "" : stamp(decision.expiresAt())),
                quote(decision == null ? "" : decision.comment()));
    }

    private static String component(ObservedIssue issue) {
        if (issue.packageName() == null) {
            return "";
        }
        return issue.packageVersion() == null
                ? issue.packageName()
                : issue.packageName() + " " + issue.packageVersion();
    }

    private static String stamp(Instant instant) {
        return instant == null ? "" : instant.toString();
    }

    /**
     * Every field quoted, and quotes doubled inside.
     *
     * <p><b>Quoted unconditionally rather than when it looks necessary.</b> A triage comment is
     * free text written by whoever triaged: it contains commas, newlines and quotation marks as
     * a matter of course, and a rule that decides per field is a rule with a case nobody thought
     * of — which produces a file that opens fine and has one column too many on the row that
     * matters.
     */
    private static String quote(String value) {
        return '"' + (value == null ? "" : value.replace("\"", "\"\"")) + '"';
    }
}
