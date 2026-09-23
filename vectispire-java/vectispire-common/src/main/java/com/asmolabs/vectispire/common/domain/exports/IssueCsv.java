package com.asmolabs.vectispire.common.domain.exports;

import com.asmolabs.vectispire.common.domain.issues.IssueState;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Flat CSV of the issues, one row each, for reporting and spreadsheets.
 *
 * <p>Deliberately one column per stored field rather than a chosen subset: the people who ask
 * for CSV are the ones who want to cross-reference it themselves.
 *
 * <p><b>The column list and the value list are the same list.</b> The NestJS version kept
 * twenty-five header names in one array and twenty-five expressions in another, positionally
 * matched; inserting a column in one and not the other shifts every value after it into the
 * wrong header, and produces a file that looks perfectly well-formed. Here each column carries
 * its own name and its own extractor, so the two cannot drift.
 */
public final class IssueCsv {

    private IssueCsv() {}

    /** One column: its header, and where its value comes from. */
    public enum Column {
        ID("id", issue -> String.valueOf(issue.id())),
        TYPE("type", issue -> issue.type() == null ? "" : issue.type().wireName()),
        IDENTIFIER("identifier", ExportableIssue::identifier),
        SEVERITY("severity", issue -> issue.severity().wireName()),
        CVSS_SCORE("cvss_score", issue -> number(issue.cvssScore())),
        EPSS_SCORE("epss_score", issue -> number(issue.epssScore())),
        IS_KEV("is_kev", issue -> Boolean.toString(issue.kev())),
        PACKAGE_NAME("package_name", ExportableIssue::packageName),
        PACKAGE_VERSION("package_version", ExportableIssue::packageVersion),
        PURL("purl", ExportableIssue::purl),
        DEPENDENCY("dependency", issue -> issue.directness().label()),
        FILE_PATH("file_path", ExportableIssue::filePath),
        LINE("line", issue -> issue.line() == null || issue.line() == 0 ? "" : String.valueOf(issue.line())),
        FIX_STATE("fix_state", issue -> issue.fixState() == null ? "" : issue.fixState().wireName()),
        FIX_VERSIONS("fix_versions", ExportableIssue::fixVersions),
        STATE("state", issue -> (issue.resolved() ? IssueState.RESOLVED : IssueState.OPEN).wireName()),
        TRIAGE_STATUS("triage_status", issue -> issue.triageStatus() == null ? "" : issue.triageStatus().wireName()),
        TRIAGE_JUSTIFICATION("triage_justification", ExportableIssue::triageJustification),
        TRIAGED_BY("triaged_by", ExportableIssue::triagedBy),
        TRIAGED_AT("triaged_at", issue -> instant(issue.triagedAt())),
        TRIAGE_EXPIRES_AT("triage_expires_at", issue -> instant(issue.triageExpiresAt())),
        FIRST_SEEN_AT("first_seen_at", issue -> instant(issue.firstSeenAt())),
        LAST_SEEN_AT("last_seen_at", issue -> instant(issue.lastSeenAt())),
        TIMES_SEEN("times_seen", issue -> String.valueOf(issue.timesSeen() == null || issue.timesSeen() == 0 ? 1 : issue.timesSeen())),
        LINK("link", ExportableIssue::link);

        private final String header;
        private final Function<ExportableIssue, String> extractor;

        Column(String header, Function<ExportableIssue, String> extractor) {
            this.header = header;
            this.extractor = extractor;
        }

        public String header() {
            return header;
        }

        String valueFrom(ExportableIssue issue) {
            String value = extractor.apply(issue);
            return value == null ? "" : value;
        }
    }

    /**
     * Rows are terminated with CRLF, including the last one.
     *
     * <p>RFC 4180. Using a bare newline produces a file most tools read anyway, which is the
     * problem: the divergence surfaces only when a strict consumer refuses it, long after
     * anybody remembers writing this line.
     */
    private static final String ROW_TERMINATOR = "\r\n";

    public static String build(Collection<ExportableIssue> issues) {
        StringBuilder csv = new StringBuilder();

        csv.append(Arrays.stream(Column.values()).map(Column::header).reduce((a, b) -> a + "," + b).orElse(""));
        csv.append(ROW_TERMINATOR);

        for (ExportableIssue issue : issues) {
            String[] cells = Arrays.stream(Column.values())
                    .map(column -> quote(column.valueFrom(issue)))
                    .toArray(String[]::new);
            csv.append(String.join(",", cells)).append(ROW_TERMINATOR);
        }

        return csv.toString();
    }

    private static final Pattern NEEDS_QUOTING = Pattern.compile("[\",\\r\\n]");

    /**
     * Minimal quoting, <b>preceded by formula neutralization</b> — see {@link SpreadsheetCells}
     * for why the order matters and cannot be reversed.
     */
    private static String quote(String value) {
        String safe = SpreadsheetCells.neutralize(value);
        if (!NEEDS_QUOTING.matcher(safe).find()) {
            return safe;
        }
        return '"' + safe.replace("\"", "\"\"") + '"';
    }

    private static String number(Double value) {
        if (value == null) {
            return "";
        }
        // Whole scores render as `7` rather than `7.0`: the column is read by people and by
        // spreadsheets, and neither gains from a trailing zero.
        return value == Math.floor(value) && !value.isInfinite()
                ? String.valueOf(value.longValue())
                : String.valueOf(value);
    }

    private static String instant(Instant value) {
        // Canonicalized like everywhere else: a CSV compared byte for byte must not depend on
        // the timezone of the machine that produced it.
        return value == null ? "" : Digests.canonical(value);
    }
}
