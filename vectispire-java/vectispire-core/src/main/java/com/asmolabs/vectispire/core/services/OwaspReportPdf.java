package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.aireview.OwaspMarkdown;
import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * The OWASP report as a document somebody can send on.
 *
 * <h2>Why it renders Markdown by hand</h2>
 *
 * <p>The model answers in Markdown, which is right — it is the format that survives being read
 * as plain text on the screen. A PDF of that same text, printed verbatim, would be a wall of
 * hashes and asterisks; a full Markdown engine plus an HTML-to-PDF stack would be two rendering
 * pipelines to keep correct for a document of one shape. What is handled here is what the prompt
 * asks the model to produce: headings, bullets, numbered items, bold runs. <b>Anything else is
 * printed as written</b> rather than dropped — an unrecognised construct that disappears is how
 * a report quietly loses a paragraph.
 *
 * <h2>The provenance is on the first page, not in a footer</h2>
 *
 * <p>This document leaves Vectispire and gets forwarded. A reader who cannot see which model wrote
 * it, from which scan, on which version, has a security report with no way to judge its age or
 * its author — and the caveat that a model wrote it is the first thing an auditor needs, not a
 * detail at the bottom.
 */
public final class OwaspReportPdf {

    private OwaspReportPdf() {}

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    /** Vectispire's ink: a deep slate for structure, a warm accent for the category headings. */
    private static final Color INK = new Color(0x1F, 0x2A, 0x37);
    private static final Color ACCENT = new Color(0x9A, 0x3F, 0x3F);
    private static final Color MUTED = new Color(0x6B, 0x72, 0x80);
    private static final Color BAND = new Color(0xF3, 0xF4, 0xF6);

    /**
     * @param subject the target, so the document names what it is about without its filename
     * @param model recorded on the page: comparing two reports written by different models
     *     without knowing it is a trap, and the reader is usually not the operator
     */
    public record Subject(
            String targetName,
            String branch,
            String projectVersion,
            String model,
            Long scanId,
            Instant scanAt,
            Instant generatedAt,
            long openIssues) {}

    public static byte[] render(Subject subject, String markdown) {
        try (PDDocument document = new PDDocument();
                ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {

            ReportCursor cursor = new ReportCursor(document);
            cover(cursor, subject);
            body(cursor, markdown);
            cursor.close("Vectispire — OWASP report — " + subject.targetName());

            document.save(bytes);
            return bytes.toByteArray();
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not render the OWASP report", failed);
        }
    }

    private static void cover(ReportCursor cursor, Subject subject) {
        cursor.text("OWASP Top 10 — posture report", ReportCursor.HELVETICA_BOLD_16, INK);
        cursor.rule(ACCENT);
        cursor.gap();

        cursor.text(subject.targetName(), ReportCursor.HELVETICA_BOLD_12, INK);
        cursor.text(
                subject.branch()
                        + (subject.projectVersion() == null || subject.projectVersion().isBlank()
                                ? ""
                                : "  ·  version " + subject.projectVersion()),
                ReportCursor.HELVETICA_10,
                MUTED);
        cursor.gap();

        cursor.band(ReportCursor.LINE * 4.4f, BAND);
        cursor.text("Open findings at the time of writing: " + subject.openIssues(), ReportCursor.HELVETICA_10, INK);
        cursor.text(
                "Built from scan #" + subject.scanId()
                        + (subject.scanAt() == null ? "" : " of " + STAMP.format(subject.scanAt())),
                ReportCursor.HELVETICA_10,
                INK);
        cursor.text("Written by " + subject.model(), ReportCursor.HELVETICA_10, INK);
        cursor.text("Generated " + STAMP.format(subject.generatedAt()), ReportCursor.HELVETICA_10, INK);
        cursor.gap();
        cursor.gap();

        // **The caveat before the content, and in the document rather than beside it.** This page
        // outlives the screen that carried the warning. A reader who takes model prose for
        // scanner output will act on a sentence nobody verified.
        cursor.text("How to read this", ReportCursor.HELVETICA_BOLD_10, INK);
        cursor.paragraph(
                "Every fact below comes from an automated scanner. A language model grouped those findings under "
                        + "the OWASP categories and wrote the prose; it detected nothing itself, and nothing it "
                        + "says becomes an issue or reaches a build gate. A category with no finding means no "
                        + "scanner here looked for it — not that the code is sound.",
                ReportCursor.HELVETICA_9,
                0);
        cursor.gap();
        cursor.rule(MUTED);
        cursor.gap();
    }

    /**
     * <b>The parsing lives in the domain, not here.</b> This document and the screen render the
     * same report, and the first version read the Markdown twice in two languages — two answers
     * to "what is a heading", drifting on the first construct one of them learned to handle.
     */
    private static void body(ReportCursor cursor, String markdown) {
        List<OwaspMarkdown.Block> blocks = OwaspMarkdown.parse(markdown);
        if (blocks.isEmpty()) {
            cursor.paragraph("The model returned an empty report.", ReportCursor.HELVETICA_10, 0);
            return;
        }

        // **Spacing belongs here, not in the blocks.** A blank line in the source is presentation,
        // and encoding it as a block would make the parser answer a question the screen and the
        // page answer differently — one has CSS margins, the other has millimetres.
        OwaspMarkdown.Kind previous = null;
        for (OwaspMarkdown.Block block : blocks) {
            boolean listItem = block.kind() == OwaspMarkdown.Kind.BULLET
                    || block.kind() == OwaspMarkdown.Kind.NUMBERED;
            if (previous == OwaspMarkdown.Kind.PARAGRAPH
                    || (previous != null && !listItem && (previous == OwaspMarkdown.Kind.BULLET
                            || previous == OwaspMarkdown.Kind.NUMBERED))) {
                cursor.gap();
            }
            previous = block.kind();

            switch (block.kind()) {
                case CATEGORY -> {
                    cursor.gap();
                    cursor.band(ReportCursor.LINE * 1.5f, BAND);
                    cursor.text(block.text(), ReportCursor.HELVETICA_BOLD_12, ACCENT);
                }
                case HEADING -> {
                    cursor.gap();
                    cursor.text(
                            block.text(),
                            block.level() <= 2 ? ReportCursor.HELVETICA_BOLD_12 : ReportCursor.HELVETICA_BOLD_10,
                            INK);
                    if (block.level() <= 2) {
                        cursor.rule(MUTED);
                    }
                }
                // The marker is drawn apart from the text so the wrapped remainder lines up under
                // the first word rather than under the bullet.
                case BULLET -> {
                    cursor.text("\u2022", ReportCursor.HELVETICA_10, ACCENT);
                    cursor.up();
                    cursor.paragraph(block.text(), ReportCursor.HELVETICA_10, 14);
                }
                case NUMBERED -> {
                    cursor.text(block.marker() + ".", ReportCursor.HELVETICA_BOLD_10, ACCENT);
                    cursor.up();
                    cursor.paragraph(block.text(), ReportCursor.HELVETICA_10, 18);
                }
                case BLOCKQUOTE -> {
                    cursor.gap();
                    cursor.callout(block.text(), ReportCursor.HELVETICA_9, BAND, ACCENT);
                }
                case TABLE -> {
                    cursor.gap();
                    if (block.headers() != null && !block.headers().isEmpty()) {
                        String h1 = block.headers().get(0);
                        String h2 = block.headers().size() > 1 ? block.headers().get(1) : "";
                        cursor.tableRow2(h1, h2, 160, ReportCursor.HELVETICA_BOLD_9, ReportCursor.HELVETICA_BOLD_9, ACCENT, ACCENT);
                        cursor.rule(MUTED);
                    }
                    if (block.rows() != null) {
                        for (List<String> row : block.rows()) {
                            if (row.size() >= 2) {
                                cursor.tableRow2(row.get(0), row.get(1), 160, ReportCursor.HELVETICA_BOLD_9, ReportCursor.HELVETICA_9, INK, INK);
                            } else if (!row.isEmpty()) {
                                cursor.paragraph(row.get(0), ReportCursor.HELVETICA_9, 0);
                            }
                        }
                    }
                }
                case PARAGRAPH -> cursor.paragraph(block.text(), ReportCursor.HELVETICA_10, 0);
            }
        }
    }

}
