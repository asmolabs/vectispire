package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.core.services.TriageHistory.Decision;
import com.asmolabs.zanshin.core.services.TriageHistory.ObservedIssue;
import com.asmolabs.zanshin.core.services.TriageHistory.Scan;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * The trail as a document, for somebody who has to be convinced and does not have Zanshin.
 *
 * <p><b>It leads with what was decided, not with what was found.</b> A backlog listing answers
 * "what is wrong"; this document answers "what did you do about it", which is a different
 * question asked by a different reader — an auditor, a client's security team, a committee.
 *
 * <p><b>A scan that observed nothing says so, in the scan's own line.</b> The temptation is to
 * print only scans with findings, which would produce a clean-looking history out of a target
 * nobody managed to clone. The same trap the posture report names: an empty result and an absent
 * one are not the same claim, and only one of them is reassuring.
 *
 * <p><b>An issue nobody triaged is printed with "no decision recorded".</b> Silence would let it
 * pass for a decision that was not written down; the sentence makes the gap part of the record,
 * which is what an audit is for.
 */
public final class TriageHistoryReport {

    private TriageHistoryReport() {}

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);

    private static final float[] COLUMNS = {0, 60, 200, 330, 430};
    private static final int[] WIDTHS = {10, 24, 22, 17, 18};

    public static byte[] render(TriageHistory.Repository repository, List<Scan> scans, Instant generatedAt) {
        try (PDDocument document = new PDDocument();
                ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {

            ReportCursor cursor = new ReportCursor(document);
            heading(cursor, repository, scans, generatedAt);
            for (Scan scan : scans) {
                scan(cursor, scan);
            }
            cursor.close();

            document.save(bytes);
            return bytes.toByteArray();
        } catch (IOException failed) {
            // The caller is an HTTP handler with nothing useful to do about it, and a checked
            // exception here would spread through three layers to be rethrown at each.
            throw new UncheckedIOException("Could not render the history report", failed);
        }
    }

    private static void heading(
            ReportCursor cursor, TriageHistory.Repository repository, List<Scan> scans, Instant generatedAt) {

        cursor.text("Zanshin — detection and triage history", ReportCursor.HELVETICA_BOLD_16);
        cursor.gap();
        cursor.text(repository.name(), ReportCursor.HELVETICA_BOLD_12);
        cursor.text(repository.url(), ReportCursor.HELVETICA_9);
        cursor.text("Generated " + STAMP.format(generatedAt), ReportCursor.HELVETICA_9);
        cursor.gap();

        cursor.text(
                "Current version: " + (repository.version() == null ? "unknown" : repository.version())
                        + (repository.projectType() == null ? "" : " (" + repository.projectType() + ")"),
                ReportCursor.HELVETICA_10);
        cursor.text("Scans covered: " + scans.size(), ReportCursor.HELVETICA_10);
        cursor.text("Open issues today: " + repository.openIssues(), ReportCursor.HELVETICA_10);
        cursor.text("Triage decisions recorded: " + repository.decisions(), ReportCursor.HELVETICA_10);

        if (repository.decisions() == 0) {
            cursor.gap();
            // Said in a sentence rather than left as a zero. A reader who sees "0" without this
            // cannot tell an untriaged backlog from a history that predates the recording of
            // decisions, and the two say very different things about the process.
            cursor.text("No triage decision has been recorded for this target.", ReportCursor.HELVETICA_BOLD_10);
            cursor.text(
                    "Either nothing has been triaged, or the decisions predate the recording of this history.",
                    ReportCursor.HELVETICA_9);
        }
        cursor.gap();
    }

    private static void scan(ReportCursor cursor, Scan scan) {
        cursor.gap();
        cursor.text(
                "Scan #" + scan.id() + " — " + DAY.format(scan.createdAt())
                        + " — " + scan.branch()
                        + (scan.version() == null ? "" : " — version " + scan.version()),
                ReportCursor.HELVETICA_BOLD_12);

        String counts = scan.findingsCount() + " findings, " + scan.newIssuesCount() + " new, "
                + scan.resolvedIssuesCount() + " resolved";
        cursor.text(scan.status() + " — " + counts, ReportCursor.HELVETICA_9);

        if (scan.error() != null && !scan.error().isBlank()) {
            // Printed even for a completed scan: this is where a step that looked at nothing is
            // recorded, and a document that omitted it would present a partial scan as a full one.
            cursor.text("Reported: " + ReportCursor.truncate(scan.error(), 95), ReportCursor.HELVETICA_9);
        }

        if (scan.issues().isEmpty()) {
            cursor.text("No issue observed by this scan.", ReportCursor.HELVETICA_9);
            return;
        }

        cursor.row(
                new String[] {"SEVERITY", "IDENTIFIER", "COMPONENT", "STATE", "TRIAGE"},
                COLUMNS,
                WIDTHS,
                ReportCursor.HELVETICA_BOLD_9);

        for (ObservedIssue issue : scan.issues()) {
            cursor.row(
                    new String[] {
                        blank(issue.severity(), "unknown"),
                        blank(issue.identifier(), "—"),
                        component(issue),
                        blank(issue.state(), "—"),
                        blank(issue.triageStatus(), "—")
                    },
                    COLUMNS,
                    WIDTHS,
                    ReportCursor.HELVETICA_9);

            decisions(cursor, issue);
        }
    }

    private static void decisions(ReportCursor cursor, ObservedIssue issue) {
        if (issue.decisions().isEmpty()) {
            cursor.text("      no decision recorded", ReportCursor.HELVETICA_9);
            return;
        }
        for (Decision decision : issue.decisions()) {
            String who = decision.actor() == null
                    // The lapse of a deadline is not a person's decision, and naming one would be
                    // attributing an action to somebody who did not take it.
                    ? "expired automatically"
                    : "by " + decision.actor();
            String line = "      " + DAY.format(decision.occurredAt()) + " — "
                    + decision.fromStatus() + " -> " + decision.toStatus()
                    + (decision.justification() == null ? "" : " (" + decision.justification() + ")")
                    + " " + who
                    + (decision.version() == null ? "" : " on " + decision.version());
            cursor.text(ReportCursor.truncate(line, 110), ReportCursor.HELVETICA_9);

            if (decision.comment() != null && !decision.comment().isBlank()) {
                cursor.text(
                        ReportCursor.truncate("         \"" + decision.comment() + "\"", 110),
                        ReportCursor.HELVETICA_9);
            }
        }
    }

    private static String component(ObservedIssue issue) {
        if (issue.packageName() != null) {
            return issue.packageVersion() == null
                    ? issue.packageName()
                    : issue.packageName() + " " + issue.packageVersion();
        }
        return blank(issue.filePath(), "—");
    }

    private static String blank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
