package com.asmolabs.vectispire.reportdemo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * An Office Open XML workbook, written with the JDK alone and the same bytes every time.
 *
 * <p><b>Deterministic, because the platform's provenance relies on it</b> (decision 0035 §3): whoever
 * doubts a document renders the kept export again with the pinned image and compares. So nothing here
 * reads a clock or draws a random number. Every entry is dated 1980-02-01 00:00, given as a local date-time
 * so the host's time zone cannot move it — not 1980-01-01, which the JDK reads as "before the format's
 * epoch" and stores again as an extended timestamp converted through the host's zone, so that the same
 * export gave other bytes in another zone (the test pins it) — the parts
 * go in one fixed order, the compression level is fixed, and no document-properties part carries a
 * "created" instant at all.
 *
 * <p><b>What a type check reads first</b> (0035 §3, the {@code WorkbookReader} the platform applies):
 * {@code [Content_Types].xml} first and naming the workbook as a {@code sheet.main+xml}, a package
 * relationship to it, no {@code vbaProject.bin}, no macro sheet, no external relationship, no archive
 * inside the archive, and every cell's text within Excel's 32,767 characters.
 *
 * <p><b>Text cells are inline strings</b>, not a shared-strings table: one part fewer, nothing to keep in
 * step, and each cell readable where it stands. Numbers are numbers; instants stay the ISO text the export
 * gave, since a serial date would need a time zone and a rounding nobody asked for.
 */
final class Xlsx {

    /** Excel's ceiling on a cell's text; a reader that enforces it refuses the whole file, not the cell. */
    static final int MAX_CELL_TEXT = 32_767;

    private static final LocalDateTime ZIP_EPOCH = LocalDateTime.of(1980, 2, 1, 0, 0);

    private static final String MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    private static final String RELATIONSHIPS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    private static final String PACKAGE_RELATIONSHIPS = "http://schemas.openxmlformats.org/package/2006/relationships";
    private static final String DECLARATION = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";

    /** A cell's content: text, a whole number, or nothing. */
    sealed interface Cell {
        record Text(String value) implements Cell {}

        record Number(long value) implements Cell {}

        record Decimal(double value) implements Cell {}

        record Empty() implements Cell {}

        Cell EMPTY = new Empty();

        static Cell of(String value) {
            return value == null ? EMPTY : new Text(value);
        }

        static Cell of(long value) {
            return new Number(value);
        }
    }

    /** A row, and whether it is a heading — bold, the one style the workbook carries. */
    record Row(List<Cell> cells, boolean heading) {
        Row {
            cells = List.copyOf(cells);
        }

        static Row of(Cell... cells) {
            return new Row(List.of(cells), false);
        }

        static Row heading(String... titles) {
            return new Row(List.of(titles).stream().map(Cell::of).toList(), true);
        }

        static Row blank() {
            return new Row(List.of(), false);
        }
    }

    /** A worksheet: its name, its column widths in characters, its rows from the first. */
    record Sheet(String name, List<Integer> widths, List<Row> rows) {
        Sheet {
            if (name.isEmpty() || name.length() > 31 || name.chars().anyMatch(c -> "[]:*?/\\".indexOf(c) >= 0)) {
                throw new IllegalArgumentException("Not a sheet name Excel accepts: " + name);
            }
            widths = List.copyOf(widths);
            rows = List.copyOf(rows);
        }
    }

    private Xlsx() {}

    static byte[] write(List<Sheet> sheets) {
        List<Part> parts = new ArrayList<>();
        parts.add(new Part("[Content_Types].xml", contentTypes(sheets.size())));
        parts.add(new Part("_rels/.rels", DECLARATION + "<Relationships xmlns=\"" + PACKAGE_RELATIONSHIPS + "\">"
                + "<Relationship Id=\"rId1\" Type=\"" + RELATIONSHIPS + "/officeDocument\" Target=\"xl/workbook.xml\"/>"
                + "</Relationships>"));
        parts.add(new Part("xl/workbook.xml", workbook(sheets)));
        parts.add(new Part("xl/_rels/workbook.xml.rels", workbookRelationships(sheets.size())));
        parts.add(new Part("xl/styles.xml", STYLES));
        for (int i = 0; i < sheets.size(); i++) {
            parts.add(new Part("xl/worksheets/sheet" + (i + 1) + ".xml", worksheet(sheets.get(i))));
        }
        return zip(parts);
    }

    private record Part(String name, String xml) {}

    private static byte[] zip(List<Part> parts) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes, StandardCharsets.UTF_8)) {
            zip.setMethod(ZipOutputStream.DEFLATED);
            zip.setLevel(Deflater.DEFAULT_COMPRESSION);
            for (Part part : parts) {
                ZipEntry entry = new ZipEntry(part.name());
                entry.setTimeLocal(ZIP_EPOCH);
                zip.putNextEntry(entry);
                zip.write(part.xml().getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        } catch (IOException impossible) {
            // A byte array does not fail; a zip of one would be a bug of this class.
            throw new UncheckedIOException(impossible);
        }
        return bytes.toByteArray();
    }

    private static String contentTypes(int sheets) {
        StringBuilder xml = new StringBuilder(DECLARATION)
                .append("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">")
                .append("<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>")
                .append("<Default Extension=\"xml\" ContentType=\"application/xml\"/>")
                .append("<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>")
                .append("<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>");
        for (int i = 1; i <= sheets; i++) {
            xml.append("<Override PartName=\"/xl/worksheets/sheet").append(i)
                    .append(".xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>");
        }
        return xml.append("</Types>").toString();
    }

    private static String workbook(List<Sheet> sheets) {
        StringBuilder xml = new StringBuilder(DECLARATION)
                .append("<workbook xmlns=\"").append(MAIN).append("\" xmlns:r=\"").append(RELATIONSHIPS).append("\"><sheets>");
        for (int i = 0; i < sheets.size(); i++) {
            xml.append("<sheet name=\"").append(escape(sheets.get(i).name())).append("\" sheetId=\"").append(i + 1)
                    .append("\" r:id=\"rId").append(i + 1).append("\"/>");
        }
        return xml.append("</sheets></workbook>").toString();
    }

    private static String workbookRelationships(int sheets) {
        StringBuilder xml = new StringBuilder(DECLARATION)
                .append("<Relationships xmlns=\"").append(PACKAGE_RELATIONSHIPS).append("\">");
        for (int i = 1; i <= sheets; i++) {
            xml.append("<Relationship Id=\"rId").append(i).append("\" Type=\"").append(RELATIONSHIPS)
                    .append("/worksheet\" Target=\"worksheets/sheet").append(i).append(".xml\"/>");
        }
        xml.append("<Relationship Id=\"rId").append(sheets + 1).append("\" Type=\"").append(RELATIONSHIPS)
                .append("/styles\" Target=\"styles.xml\"/>");
        return xml.append("</Relationships>").toString();
    }

    /** Two fonts — regular and bold — and the two formats that use them; the fills and border Excel requires. */
    private static final String STYLES = DECLARATION + "<styleSheet xmlns=\"" + MAIN + "\">"
            + "<fonts count=\"2\"><font><sz val=\"11\"/><name val=\"Calibri\"/></font>"
            + "<font><b/><sz val=\"11\"/><name val=\"Calibri\"/></font></fonts>"
            + "<fills count=\"2\"><fill><patternFill patternType=\"none\"/></fill>"
            + "<fill><patternFill patternType=\"gray125\"/></fill></fills>"
            + "<borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders>"
            + "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>"
            + "<cellXfs count=\"2\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>"
            + "<xf numFmtId=\"0\" fontId=\"1\" fillId=\"0\" borderId=\"0\" xfId=\"0\" applyFont=\"1\"/></cellXfs>"
            + "<cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles>"
            + "</styleSheet>";

    private static String worksheet(Sheet sheet) {
        StringBuilder xml = new StringBuilder(DECLARATION)
                .append("<worksheet xmlns=\"").append(MAIN).append("\">");
        if (!sheet.widths().isEmpty()) {
            xml.append("<cols>");
            for (int i = 0; i < sheet.widths().size(); i++) {
                xml.append("<col min=\"").append(i + 1).append("\" max=\"").append(i + 1).append("\" width=\"")
                        .append(sheet.widths().get(i)).append("\" customWidth=\"1\"/>");
            }
            xml.append("</cols>");
        }
        xml.append("<sheetData>");
        int r = 0;
        for (Row row : sheet.rows()) {
            r++;
            if (row.cells().stream().allMatch(cell -> cell instanceof Cell.Empty)) {
                continue;
            }
            xml.append("<row r=\"").append(r).append("\">");
            for (int c = 0; c < row.cells().size(); c++) {
                cell(xml, column(c) + r, row.cells().get(c), row.heading());
            }
            xml.append("</row>");
        }
        return xml.append("</sheetData></worksheet>").toString();
    }

    private static void cell(StringBuilder xml, String reference, Cell cell, boolean heading) {
        String style = heading ? " s=\"1\"" : "";
        switch (cell) {
            case Cell.Empty empty -> {
                // Nothing written: a cell with no value is a cell that is not there.
            }
            case Cell.Text text -> xml.append("<c r=\"").append(reference).append("\"").append(style)
                    .append(" t=\"inlineStr\"><is><t xml:space=\"preserve\">").append(escape(clip(text.value())))
                    .append("</t></is></c>");
            case Cell.Number number -> xml.append("<c r=\"").append(reference).append("\"").append(style)
                    .append("><v>").append(number.value()).append("</v></c>");
            case Cell.Decimal decimal -> {
                if (Double.isFinite(decimal.value())) {
                    xml.append("<c r=\"").append(reference).append("\"").append(style).append("><v>")
                            .append(Double.toString(decimal.value())).append("</v></c>");
                }
            }
        }
    }

    /** A, B, … Z, AA, AB … — the column's letters. */
    static String column(int index) {
        StringBuilder letters = new StringBuilder();
        for (int n = index + 1; n > 0; n = (n - 1) / 26) {
            letters.insert(0, (char) ('A' + (n - 1) % 26));
        }
        return letters.toString();
    }

    /**
     * Within Excel's ceiling, and saying so: a text cut silently would read as the whole of it. Cut at a code
     * point, never between the two halves of a surrogate pair.
     */
    static String clip(String text) {
        if (text.length() <= MAX_CELL_TEXT) {
            return text;
        }
        String marker = " … [cut: " + text.length() + " characters in the export]";
        int end = MAX_CELL_TEXT - marker.length();
        if (Character.isHighSurrogate(text.charAt(end - 1))) {
            end--;
        }
        return text.substring(0, end) + marker;
    }

    /**
     * Escaped for XML 1.0, and every character XML 1.0 cannot carry — the C0 controls but tab, newline and
     * return, a lone surrogate, U+FFFE and U+FFFF — replaced by U+FFFD: a part that does not parse is a
     * workbook nobody opens, and the export is JSON, which carries all of them.
     */
    static String escape(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '&' -> out.append("&amp;");
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '"' -> out.append("&quot;");
                case '\t', '\n', '\r' -> out.append(c);
                default -> {
                    if (Character.isHighSurrogate(c) && i + 1 < text.length() && Character.isLowSurrogate(text.charAt(i + 1))) {
                        out.append(c).append(text.charAt(++i));
                    } else if (c < 0x20 || Character.isSurrogate(c) || c == '\uFFFE' || c == '\uFFFF') {
                        out.append('\uFFFD');
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }
}
