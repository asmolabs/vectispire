package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.aireview.AdviceLanguage;
import com.asmolabs.vectispire.common.domain.aireview.OwaspMarkdown;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.reporting.ReportCursor;
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
 *
 * <h2>The reader's language, and the grid beside the prose</h2>
 *
 * <p>The document was English whoever asked for it, and carried the model's prose alone. Its own words
 * now follow the requester's language ({@link OwaspReportWords}); the model's text is printed as written.
 * And it carries the coverage grid the screen shows above the report: the prose is commentary, the grid is
 * what the rules say, and a file forwarded without the second asks its reader to trust the first.
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
     * @param placedByRule the model was handed each finding's category ({@code
     *     OwaspReview.placedByRule}); a report written before that was placed by the model, and the
     *     page says which of the two it is
     */
    public record Subject(
            String targetName,
            String branch,
            String projectVersion,
            String model,
            Long scanId,
            Instant scanAt,
            Instant generatedAt,
            long openIssues,
            String brandName,
            boolean placedByRule) {

        /** A report whose findings' categories were not recorded as handed over: the model placed them. */
        public Subject(
                String targetName,
                String branch,
                String projectVersion,
                String model,
                Long scanId,
                Instant scanAt,
                Instant generatedAt,
                long openIssues,
                String brandName) {
            this(targetName, branch, projectVersion, model, scanId, scanAt, generatedAt, openIssues, brandName, false);
        }

        public Subject(
                String targetName,
                String branch,
                String projectVersion,
                String model,
                Long scanId,
                Instant scanAt,
                Instant generatedAt,
                long openIssues) {
            this(targetName, branch, projectVersion, model, scanId, scanAt, generatedAt, openIssues, "Vectispire");
        }
    }

    /**
     * @param coverage the repository's coverage grid as the rules read it now — the screen's grid, beside
     *     the model's prose, so a forwarded document carries the evidence and not only the commentary
     * @param language the requester's: the document's own words are written in it, the model's text is not
     */
    public static byte[] render(Subject subject, String markdown, OwaspCoverage.Grid coverage, AdviceLanguage language) {
        try (PDDocument document = new PDDocument();
                ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {

            ReportCursor cursor = new ReportCursor(document);
            cover(cursor, subject, language);
            grid(cursor, coverage, language);
            body(cursor, markdown, language);
            String brand = subject.brandName() == null || subject.brandName().isBlank() ? "Vectispire" : subject.brandName();
            cursor.close(OwaspReportWords.FOOTER.in(language, brand, subject.targetName()));

            document.save(bytes);
            return bytes.toByteArray();
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not render the OWASP report", failed);
        }
    }

    private static void cover(ReportCursor cursor, Subject subject, AdviceLanguage language) {
        cursor.text(OwaspReportWords.TITLE.in(language), ReportCursor.HELVETICA_BOLD_16, INK);
        cursor.rule(ACCENT);
        cursor.gap();

        cursor.text(subject.targetName(), ReportCursor.HELVETICA_BOLD_12, INK);
        cursor.text(
                subject.branch()
                        + (subject.projectVersion() == null || subject.projectVersion().isBlank()
                                ? ""
                                : "  ·  " + OwaspReportWords.VERSION.in(language, subject.projectVersion())),
                ReportCursor.HELVETICA_10,
                MUTED);
        cursor.gap();

        cursor.band(ReportCursor.LINE * 4.4f, BAND);
        cursor.text(OwaspReportWords.OPEN_FINDINGS.in(language, subject.openIssues()), ReportCursor.HELVETICA_10, INK);
        cursor.text(
                OwaspReportWords.BUILT_FROM.in(language, subject.scanId())
                        + (subject.scanAt() == null ? "" : OwaspReportWords.SCANNED_AT.in(language, STAMP.format(subject.scanAt()))),
                ReportCursor.HELVETICA_10,
                INK);
        cursor.text(OwaspReportWords.WRITTEN_BY.in(language, subject.model()), ReportCursor.HELVETICA_10, INK);
        cursor.text(OwaspReportWords.GENERATED.in(language, STAMP.format(subject.generatedAt())), ReportCursor.HELVETICA_10, INK);
        cursor.gap();
        cursor.gap();

        // **The caveat before the content, and in the document rather than beside it.** This page
        // outlives the screen that carried the warning. A reader who takes model prose for
        // scanner output will act on a sentence nobody verified.
        cursor.text(OwaspReportWords.HOW_TO_READ.in(language), ReportCursor.HELVETICA_BOLD_10, INK);
        // **"No finding" is not one sentence.** This page used to say a category with no finding meant no
        // scanner here looked for it, which the OWASP grid contradicts: a category can be examined and come
        // back clean. Neither reading is a clean bill of health, and the page now says both.
        cursor.paragraph(
                OwaspReportWords.READ_FACTS.in(language)
                        + (subject.placedByRule()
                                ? OwaspReportWords.READ_PLACED_BY_RULE.in(language)
                                : OwaspReportWords.READ_PLACED_BY_MODEL.in(language))
                        + OwaspReportWords.READ_CAVEAT.in(language),
                ReportCursor.HELVETICA_9,
                0);
        // **The labels follow the reader; the model's text does not.** Translating it would be putting
        // words in the model's mouth, so a reader whose labels are not English is told the prose below is
        // as the model wrote it — in whatever language that was, which nothing recorded.
        if (language != AdviceLanguage.ENGLISH) {
            cursor.gap();
            cursor.paragraph(OwaspReportWords.BODY_AS_WRITTEN.in(language), ReportCursor.HELVETICA_9, 0);
        }
        cursor.gap();
        cursor.rule(MUTED);
        cursor.gap();
    }

    /**
     * The ten categories by rule, before the model's prose: what the scanners here can say of each, and
     * why, in the reader's language. The model was handed these states; printing them lets a reader check
     * its "Not evidenced" section against the evidence instead of taking it on trust.
     */
    private static void grid(ReportCursor cursor, OwaspCoverage.Grid coverage, AdviceLanguage language) {
        cursor.text(OwaspReportWords.GRID_TITLE.in(language), ReportCursor.HELVETICA_BOLD_12, INK);
        cursor.rule(MUTED);
        cursor.paragraph(OwaspReportWords.GRID_INTRO.in(language), ReportCursor.HELVETICA_9, 0);
        cursor.paragraph(
                OwaspReportWords.GRID_FIGURES.in(language, coverage.covered(), coverage.withFindings(), coverage.unmeasured()),
                ReportCursor.HELVETICA_9,
                0);
        cursor.gap();
        for (OwaspCoverage.CoverageLine line : coverage.lines()) {
            cursor.tableRow2(
                    line.id() + "  " + line.title(),
                    OwaspReportWords.state(line, language) + " — " + OwaspReportWords.reason(line, language),
                    160,
                    ReportCursor.HELVETICA_BOLD_9,
                    ReportCursor.HELVETICA_9,
                    INK,
                    INK);
        }
        cursor.gap();
        cursor.rule(MUTED);
        cursor.gap();
    }

    /**
     * <b>The parsing lives in the domain, not here.</b> This document and the screen render the
     * same report, and the first version read the Markdown twice in two languages — two answers
     * to "what is a heading", drifting on the first construct one of them learned to handle.
     */
    private static void body(ReportCursor cursor, String markdown, AdviceLanguage language) {
        List<OwaspMarkdown.Block> blocks = OwaspMarkdown.parse(markdown);
        if (blocks.isEmpty()) {
            cursor.paragraph(OwaspReportWords.EMPTY_REPORT.in(language), ReportCursor.HELVETICA_10, 0);
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
