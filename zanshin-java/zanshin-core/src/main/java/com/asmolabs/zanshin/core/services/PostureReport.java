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
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

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

    private static final float MARGIN = 50;
    private static final float LINE = 14;
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

            Cursor cursor = new Cursor(document);
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

    private static void heading(Cursor cursor, Subject subject) {
        cursor.text("Zanshin — security posture", HELVETICA_BOLD_16);
        cursor.gap();
        cursor.text(subject.targetKind() + ": " + subject.targetName(), HELVETICA_BOLD_12);
        cursor.text("Generated " + STAMP.format(subject.generatedAt()), HELVETICA_9);
        cursor.gap();

        cursor.text("Verdict: " + (subject.passing() ? "PASSING" : "FAILING"), HELVETICA_BOLD_12);
        cursor.text("Policy: " + subject.policy(), HELVETICA_10);
        cursor.text(
                "Last scan: " + (subject.lastScanAt() == null ? "never" : STAMP.format(subject.lastScanAt())),
                HELVETICA_10);

        if (!subject.observed()) {
            cursor.gap();
            // The sentence, not just the word: a reader who does not already know that an empty
            // backlog passes every policy cannot infer it from "not observed".
            cursor.text("NOT OBSERVED — " + subject.observation(), HELVETICA_BOLD_10);
            cursor.text(
                    "No scan has succeeded on this target. Its backlog is empty because nothing looked,",
                    HELVETICA_9);
            cursor.text("not because nothing is there, and an empty backlog satisfies every policy.",
                    HELVETICA_9);
        }
        cursor.gap();
    }

    private static void summary(Cursor cursor, List<ExportableIssue> issues) {
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

        cursor.text("Open findings: " + issues.size(), HELVETICA_BOLD_12);
        cursor.text(parts.isEmpty() ? "none" : String.join(" · ", parts), HELVETICA_10);
        if (kev > 0) {
            cursor.text(kev + " actively exploited (KEV)", HELVETICA_BOLD_10);
        }
        cursor.gap();
    }

    private static void table(Cursor cursor, List<ExportableIssue> issues) {
        if (issues.isEmpty()) {
            return;
        }
        cursor.text("Findings", HELVETICA_BOLD_12);
        cursor.row("SEVERITY", "IDENTIFIER", "COMPONENT", "FIX", HELVETICA_BOLD_9);

        for (ExportableIssue issue : issues) {
            cursor.row(
                    issue.severity() == null ? "unknown" : issue.severity().wireName(),
                    nullToDash(issue.identifier()),
                    component(issue),
                    nullToDash(issue.fixVersions()),
                    HELVETICA_9);
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

    /**
     * Where the next line goes, and what happens when the page runs out.
     *
     * <p><b>Pagination is the whole reason this exists.</b> PDFBox draws at coordinates and has
     * no concept of a line that does not fit: without this, a backlog of any size writes its
     * tail past the bottom edge, off the page, and the document looks complete.
     */
    private static final class Cursor {

        private final PDDocument document;
        /** Shared across pages and fonts: the Standard-14 faces agree on what they can encode. */
        private static final Map<Character, Boolean> ENCODABLE = new java.util.concurrent.ConcurrentHashMap<>();

        private PDPageContentStream stream;
        private float y;

        Cursor(PDDocument document) throws IOException {
            this.document = document;
            newPage();
        }

        private void newPage() throws IOException {
            if (stream != null) {
                stream.close();
            }
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);
            stream = new PDPageContentStream(document, page);
            y = page.getMediaBox().getHeight() - MARGIN;
        }

        void text(String value, Font font) {
            write(MARGIN, value, font);
            y -= LINE;
        }

        void row(String severity, String identifier, String component, String fix, Font font) {
            write(MARGIN, truncate(severity, 12), font);
            write(MARGIN + 70, truncate(identifier, 24), font);
            write(MARGIN + 230, truncate(component, 32), font);
            write(MARGIN + 400, truncate(fix, 22), font);
            y -= LINE;
        }

        void gap() {
            y -= LINE / 2;
        }

        private void write(float x, String value, Font font) {
            try {
                if (y < MARGIN + LINE) {
                    newPage();
                }
                stream.beginText();
                stream.setFont(font.font(), font.size());
                stream.newLineAtOffset(x, y);
                // Standard-14 fonts are WinAnsi: a character outside it throws while writing,
                // and a package name from a foreign registry is enough to produce one.
                stream.showText(encodable(value, font.font()));
                stream.endText();
            } catch (IOException failed) {
                throw new UncheckedIOException("Could not write to the report", failed);
            }
        }

        void close() throws IOException {
            stream.close();
        }

        /**
         * Replaces only what the font truly cannot write.
         *
         * <p>The first version dropped everything above code point 255, which was both too much
         * and too little: it mangled the em dash in this document's own title — WinAnsi encodes
         * it perfectly well — while a blanket range says nothing about what the font actually
         * supports. Asking the font is the only answer that stays right when the font changes.
         *
         * <p>Memoised per character: this runs once per cell, and a fifty-thousand-issue export
         * would otherwise re-ask the same question a million times.
         */
        private static String encodable(String value, PDFont font) {
            StringBuilder safe = new StringBuilder(value.length());
            for (char c : value.toCharArray()) {
                safe.append(ENCODABLE.computeIfAbsent(c, candidate -> canEncode(candidate, font)) ? c : '?');
            }
            return safe.toString();
        }

        private static boolean canEncode(char candidate, PDFont font) {
            if (candidate < 32) {
                return false;
            }
            try {
                font.encode(String.valueOf(candidate));
                return true;
            } catch (IOException | IllegalArgumentException unsupported) {
                // A package name from a registry that allows non-Latin scripts is enough to
                // reach here. One glyph lost beats a report that fails to render at all.
                return false;
            }
        }

        private static String truncate(String value, int width) {
            return value.length() <= width ? value : value.substring(0, width - 1) + "…";
        }
    }

    /** A font and its size, so a call site names both or neither. */
    private record Font(PDFont font, float size) {}

    private static final Font HELVETICA_BOLD_16 =
            new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 16);
    private static final Font HELVETICA_BOLD_12 =
            new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 12);
    private static final Font HELVETICA_BOLD_10 =
            new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 10);
    private static final Font HELVETICA_BOLD_9 =
            new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 9);
    private static final Font HELVETICA_10 = new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 10);
    private static final Font HELVETICA_9 = new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 9);
}
