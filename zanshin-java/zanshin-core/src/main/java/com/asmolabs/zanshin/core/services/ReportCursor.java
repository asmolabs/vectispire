package com.asmolabs.zanshin.core.services;

import java.awt.Color;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDPageContentStream.AppendMode;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

/**
 * Writing lines down a page, and starting a new one when the page runs out.
 *
 * <p><b>PDFBox draws at coordinates and does not know a line did not fit.</b> Without something
 * holding the vertical position, the tail of a long document is written off the page and the
 * result looks complete — every row accounted for, half of them invisible. That defect is the
 * reason this class exists, and it was found on a real backlog of 182 findings.
 *
 * <p>Extracted from {@code PostureReport} when a second document needed the same primitives.
 * Two copies of the pagination rule would be two answers to "did this page overflow", and the
 * failure mode of the wrong answer is silent.
 */
final class ReportCursor {

    static final float MARGIN = 50;
    static final float LINE = 14;

    /** A4 minus both margins: the width a wrapped line has to fit into. */
    static final float CONTENT_WIDTH = PDRectangle.A4.getWidth() - 2 * MARGIN;

    /** Shared across pages and fonts: the Standard-14 faces agree on what they can encode. */
    private static final Map<Character, Boolean> ENCODABLE = new ConcurrentHashMap<>();

    private final PDDocument document;
    private final List<PDPage> pages = new ArrayList<>();
    private PDPageContentStream stream;
    private float y;
    private Color pending;

    ReportCursor(PDDocument document) throws IOException {
        this.document = document;
        newPage();
    }

    private void newPage() throws IOException {
        if (stream != null) {
            stream.close();
        }
        PDPage page = new PDPage(PDRectangle.A4);
        document.addPage(page);
        pages.add(page);
        stream = new PDPageContentStream(document, page);
        y = page.getMediaBox().getHeight() - MARGIN;
    }

    void text(String value, Font font) {
        write(MARGIN, value, font);
        y -= LINE;
    }

    void text(String value, Font font, Color color) {
        pending = color;
        try {
            text(value, font);
        } finally {
            pending = null;
        }
    }

    /**
     * A paragraph, broken where it stops fitting.
     *
     * <p><b>The capability this class was missing.</b> Everything it rendered until now was a
     * short cell or a label written at a coordinate; prose written that way runs off the right
     * edge and the page looks fine — the same silent overflow as writing past the bottom, which
     * is the defect that made this class exist. Measured against the font rather than counted in
     * characters: a proportional face makes "iiii" and "MMMM" the same count and four times the
     * width.
     */
    void paragraph(String value, Font font, float indent) {
        if (value == null || value.isBlank()) {
            return;
        }
        float available = CONTENT_WIDTH - indent;
        StringBuilder line = new StringBuilder();

        for (String word : value.trim().split("\\s+")) {
            String candidate = line.isEmpty() ? word : line + " " + word;
            if (widthOf(candidate, font) <= available || line.isEmpty()) {
                line.setLength(0);
                line.append(candidate);
                // A single word wider than the page would loop for ever appended to nothing:
                // it is written over-wide instead, which is visible and finite.
                if (widthOf(candidate, font) > available) {
                    write(MARGIN + indent, line.toString(), font);
                    y -= LINE;
                    line.setLength(0);
                }
                continue;
            }
            write(MARGIN + indent, line.toString(), font);
            y -= LINE;
            line.setLength(0);
            line.append(word);
        }
        if (!line.isEmpty()) {
            write(MARGIN + indent, line.toString(), font);
            y -= LINE;
        }
    }

    private static float widthOf(String value, Font font) {
        try {
            return font.font().getStringWidth(encodable(value, font.font())) / 1000 * font.size();
        } catch (IOException unmeasurable) {
            // An unmeasurable string is one the font cannot encode, which `encodable` already
            // replaced. Treating it as over-wide breaks the line early rather than overflowing.
            return Float.MAX_VALUE;
        }
    }

    /** A horizontal rule, for a heading that has to separate rather than merely sit above. */
    void rule(Color color) {
        try {
            if (y < MARGIN + LINE) {
                newPage();
            }
            stream.setStrokingColor(color);
            stream.setLineWidth(0.8f);
            stream.moveTo(MARGIN, y + LINE * 0.4f);
            stream.lineTo(MARGIN + CONTENT_WIDTH, y + LINE * 0.4f);
            stream.stroke();
            stream.setStrokingColor(Color.BLACK);
            y -= LINE * 0.6f;
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not draw a rule", failed);
        }
    }

    /** A filled band behind a heading. Drawn before the text, or it would cover it. */
    void band(float height, Color color) {
        try {
            if (y < MARGIN + height + LINE) {
                newPage();
            }
            stream.setNonStrokingColor(color);
            stream.addRect(MARGIN - 6, y - height + LINE * 0.75f, CONTENT_WIDTH + 12, height);
            stream.fill();
            stream.setNonStrokingColor(Color.BLACK);
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not draw a band", failed);
        }
    }

    /**
     * A row of cells at fixed offsets from the margin.
     *
     * <p>Offsets rather than a computed layout: the documents here have four or five columns
     * whose widths are chosen for their content, and a column engine would be a second thing to
     * get right for no reader's benefit. Each cell is truncated to the width its offset allows,
     * which is what keeps a long package name out of the next column.
     */
    void row(String[] values, float[] offsets, int[] widths, Font font) {
        for (int index = 0; index < values.length; index++) {
            write(MARGIN + offsets[index], truncate(values[index] == null ? "" : values[index], widths[index]), font);
        }
        y -= LINE;
    }

    void gap() {
        y -= LINE / 2;
    }

    /**
     * Steps back onto the line just written.
     *
     * <p>For a marker and its text: a bullet drawn at the margin, then the wrapped body indented
     * beside it. Written as two calls rather than a "bullet paragraph" primitive because the
     * marker differs — a glyph, a number, a severity tag — and only the stepping back is common.
     */
    void up() {
        y += LINE;
    }

    /** Forces what follows onto a fresh page — for a section that must not start at the bottom. */
    void breakPage() throws IOException {
        newPage();
    }

    /**
     * Measures and wraps text into lines fitting within {@code maxWidth}.
     */
    static List<String> wrap(String value, Font font, float maxWidth) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        List<String> lines = new ArrayList<>();
        StringBuilder line = new StringBuilder();

        for (String word : value.trim().split("\\s+")) {
            String candidate = line.isEmpty() ? word : line + " " + word;
            if (widthOf(candidate, font) <= maxWidth || line.isEmpty()) {
                line.setLength(0);
                line.append(candidate);
                if (widthOf(candidate, font) > maxWidth) {
                    lines.add(line.toString());
                    line.setLength(0);
                }
                continue;
            }
            lines.add(line.toString());
            line.setLength(0);
            line.append(word);
        }
        if (!line.isEmpty()) {
            lines.add(line.toString());
        }
        return lines;
    }

    /**
     * Renders a 2-column table row with independent line-wrapping in each column.
     */
    void tableRow2(String col1, String col2, float col1Width, Font font1, Font font2, Color color1, Color color2) {
        float col2Width = CONTENT_WIDTH - col1Width - 16;
        List<String> col1Lines = wrap(col1, font1, col1Width);
        List<String> col2Lines = wrap(col2, font2, col2Width);
        int lineCount = Math.max(col1Lines.size(), col2Lines.size());
        if (lineCount == 0) {
            return;
        }

        float rowHeight = lineCount * LINE;
        if (y < MARGIN + rowHeight) {
            try {
                newPage();
            } catch (IOException failed) {
                throw new UncheckedIOException(failed);
            }
        }

        float startY = y;
        for (int i = 0; i < col1Lines.size(); i++) {
            y = startY - i * LINE;
            write(MARGIN, col1Lines.get(i), font1, color1);
        }
        for (int i = 0; i < col2Lines.size(); i++) {
            y = startY - i * LINE;
            write(MARGIN + col1Width + 16, col2Lines.get(i), font2, color2);
        }
        y = startY - rowHeight - LINE * 0.25f;
    }

    /**
     * Renders a styled callout / blockquote with proper height and left accent bar.
     */
    void callout(String text, Font font, Color bgColor, Color accentColor) {
        float textWidth = CONTENT_WIDTH - 24;
        List<String> lines = wrap(text, font, textWidth);
        if (lines.isEmpty()) {
            return;
        }
        float blockHeight = lines.size() * LINE + LINE * 0.6f;
        if (y < MARGIN + blockHeight) {
            try {
                newPage();
            } catch (IOException failed) {
                throw new UncheckedIOException(failed);
            }
        }

        try {
            // Background box
            stream.setNonStrokingColor(bgColor);
            stream.addRect(MARGIN, y - blockHeight + LINE * 0.75f, CONTENT_WIDTH, blockHeight);
            stream.fill();

            // Left accent bar
            stream.setNonStrokingColor(accentColor);
            stream.addRect(MARGIN, y - blockHeight + LINE * 0.75f, 3.5f, blockHeight);
            stream.fill();
            stream.setNonStrokingColor(Color.BLACK);
        } catch (IOException failed) {
            throw new UncheckedIOException(failed);
        }

        y -= LINE * 0.3f;
        for (String line : lines) {
            write(MARGIN + 12, line, font);
            y -= LINE;
        }
        y -= LINE * 0.4f;
    }

    private void write(float x, String value, Font font) {
        write(x, value, font, pending);
    }

    private void write(float x, String value, Font font, Color color) {
        try {
            if (y < MARGIN + LINE) {
                newPage();
            }
            stream.beginText();
            stream.setNonStrokingColor(color == null ? Color.BLACK : color);
            stream.setFont(font.font(), font.size());
            stream.newLineAtOffset(x, y);
            // Standard-14 fonts are WinAnsi: a character outside it throws while writing, and a
            // package name from a foreign registry is enough to produce one.
            stream.showText(encodable(value, font.font()));
            stream.endText();
            stream.setNonStrokingColor(Color.BLACK);
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not write to the report", failed);
        }
    }

    /**
     * Stamps a footer on every page, then closes.
     *
     * <p>Done at the end because a page cannot know how many follow it: "3 of 7" is a fact only
     * the finished document holds. Each page is reopened in append mode, which is the one way to
     * write onto a page whose content stream is already closed.
     */
    void close(String footer) throws IOException {
        stream.close();
        for (int index = 0; index < pages.size(); index++) {
            try (PDPageContentStream stamp =
                    new PDPageContentStream(document, pages.get(index), AppendMode.APPEND, true)) {
                stamp.beginText();
                stamp.setNonStrokingColor(Color.GRAY);
                stamp.setFont(HELVETICA_9.font(), 8);
                stamp.newLineAtOffset(MARGIN, MARGIN * 0.6f);
                stamp.showText(encodable(footer + "  ·  " + (index + 1) + " / " + pages.size(), HELVETICA_9.font()));
                stamp.endText();
            }
        }
    }

    void close() throws IOException {
        stream.close();
    }

    /**
     * Replaces only what the font truly cannot write.
     *
     * <p>The first version dropped everything above code point 255, which was both too much and
     * too little: it mangled the em dash in a document's own title — WinAnsi encodes it perfectly
     * well — while a blanket range says nothing about what the font actually supports. Asking the
     * font is the only answer that stays right when the font changes.
     *
     * <p>Memoised per character: this runs once per cell, and a fifty-thousand-issue export would
     * otherwise re-ask the same question a million times.
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
            // A package name from a registry that allows non-Latin scripts is enough to reach
            // here. One glyph lost beats a report that fails to render at all.
            return false;
        }
    }

    static String truncate(String value, int width) {
        return value.length() <= width ? value : value.substring(0, width - 1) + "…";
    }

    /** A font and its size, so a call site names both or neither. */
    record Font(PDFont font, float size) {}

    static final Font HELVETICA_BOLD_16 = new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 16);
    static final Font HELVETICA_BOLD_12 = new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 12);
    static final Font HELVETICA_BOLD_10 = new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 10);
    static final Font HELVETICA_BOLD_9 = new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), 9);
    static final Font HELVETICA_10 = new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 10);
    static final Font HELVETICA_9 = new Font(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 9);
}
