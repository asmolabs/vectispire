package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.exports.ExportableIssue;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * A target's posture, as a document somebody can hand to somebody else.
 *
 * <p><b>Not the same audience as the other exports.</b> SARIF goes to a code host, OpenVEX to a
 * downstream consumer, CSV to a spreadsheet. This one goes to a person — an auditor, a steering
 * committee — and its job is to be readable without Zanshin open. That is why it leads with the
 * verdict and the observation rather than with rows.
 *
 * <p><b>The observation is on the first page, next to the verdict.</b> A target nobody has
 * successfully scanned has an empty backlog, and an empty backlog passes every policy: printing
 * "passing" alone would turn the absence of a scan into a certificate of good health, on the one
 * artefact that outlives the screen and gets forwarded.
 *
 * <p>Drawn with primitives rather than rendered from HTML: the alternative brings an XHTML
 * parser and a CSS subset, which is a second rendering stack to keep correct for a document of
 * four sections.
 */
public final class PostureReport {

    private static final float[] COLUMNS = {0, 70, 230, 400};
    private static final int[] WIDTHS = {12, 24, 32, 22};
    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    /**
     * @param observed whether a scan ever succeeded. <b>Carried separately from {@code passing}
     *     on purpose</b>: the two are independent, and only one of them is reassuring on its own
     * @param policy what decided the verdict, named so the reader can tell a target that met a
     *     strict policy from one that met almost none
     */
    public record Subject(
            String targetName,
            String targetKind,
            boolean passing,
            boolean observed,
            String observation,
            String policy,
            Instant lastScanAt,
            Instant generatedAt) {}

    private PostureReport() {}

    public static byte[] render(Subject subject, List<ExportableIssue> issues) {
        try (PDDocument document = new PDDocument();
                ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {

            ReportCursor cursor = new ReportCursor(document);
            heading(cursor, subject);
            summary(cursor, issues);
            table(cursor, issues);
            cursor.close();

            document.save(bytes);
            return bytes.toByteArray();
        } catch (IOException failed) {
            // The caller is an HTTP handler with nothing useful to do about it, and a checked
            // exception here would spread through three layers to be rethrown at each.
            throw new UncheckedIOException("Could not render the posture report", failed);
        }
    }

    private static void heading(ReportCursor cursor, Subject subject) {
        cursor.text("Zanshin — security posture", ReportCursor.HELVETICA_BOLD_16);
        cursor.gap();
        cursor.text(subject.targetKind() + ": " + subject.targetName(), ReportCursor.HELVETICA_BOLD_12);
        cursor.text("Generated " + STAMP.format(subject.generatedAt()), ReportCursor.HELVETICA_9);
        cursor.gap();

        cursor.text("Verdict: " + (subject.passing() ? "PASSING" : "FAILING"), ReportCursor.HELVETICA_BOLD_12);
        cursor.text("Policy: " + subject.policy(), ReportCursor.HELVETICA_10);
        cursor.text(
                "Last scan: " + (subject.lastScanAt() == null ? "never" : STAMP.format(subject.lastScanAt())),
                ReportCursor.HELVETICA_10);

        if (!subject.observed()) {
            cursor.gap();
            // The sentence, not just the word: a reader who does not already know that an empty
            // backlog passes every policy cannot infer it from "not observed".
            cursor.text("NOT OBSERVED — " + subject.observation(), ReportCursor.HELVETICA_BOLD_10);
            cursor.text(
                    "No scan has succeeded on this target. Its backlog is empty because nothing looked,",
                    ReportCursor.HELVETICA_9);
            cursor.text("not because nothing is there, and an empty backlog satisfies every policy.",
                    ReportCursor.HELVETICA_9);
        }
        cursor.gap();
    }

    private static void summary(ReportCursor cursor, List<ExportableIssue> issues) {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        int kev = 0;
        for (ExportableIssue issue : issues) {
            counts.merge(issue.severity() == null ? Severity.UNKNOWN : issue.severity(), 1, Integer::sum);
            if (issue.kev()) {
                kev++;
            }
        }

        List<String> parts = new ArrayList<>();
        for (Severity severity : Severity.values()) {
            int count = counts.getOrDefault(severity, 0);
            if (count > 0) {
                parts.add(count + " " + severity.wireName());
            }
        }

        cursor.text("Open findings: " + issues.size(), ReportCursor.HELVETICA_BOLD_12);
        cursor.text(parts.isEmpty() ? "none" : String.join(" · ", parts), ReportCursor.HELVETICA_10);
        if (kev > 0) {
            cursor.text(kev + " actively exploited (KEV)", ReportCursor.HELVETICA_BOLD_10);
        }
        cursor.gap();
    }

    private static void table(ReportCursor cursor, List<ExportableIssue> issues) {
        if (issues.isEmpty()) {
            return;
        }
        cursor.text("Findings", ReportCursor.HELVETICA_BOLD_12);
        cursor.row(new String[] {"SEVERITY", "IDENTIFIER", "COMPONENT", "FIX"}, COLUMNS, WIDTHS, ReportCursor.HELVETICA_BOLD_9);

        for (ExportableIssue issue : issues) {
            cursor.row(
                    new String[] {
                        issue.severity() == null ? "unknown" : issue.severity().wireName(),
                        nullToDash(issue.identifier()),
                        component(issue),
                        nullToDash(issue.fixVersions())
                    },
                    COLUMNS,
                    WIDTHS,
                    ReportCursor.HELVETICA_9);
        }
    }

    private static String component(ExportableIssue issue) {
        if (issue.packageName() != null) {
            return issue.packageVersion() == null
                    ? issue.packageName()
                    : issue.packageName() + " " + issue.packageVersion();
        }
        return nullToDash(issue.filePath());
    }

    private static String nullToDash(String value) {
        return value == null || value.isBlank() ? "—" : value;
    }

}
