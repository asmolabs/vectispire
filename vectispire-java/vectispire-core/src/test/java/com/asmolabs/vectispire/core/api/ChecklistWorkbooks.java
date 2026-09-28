package com.asmolabs.vectispire.core.api;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * A checklist template workbook written part by part from invented controls — never a real template,
 * whose content is its organisation's (decision 0032). The shape of the first one: instructions, the
 * checklist with a merged title, a date formula, product and author cells, a column header row, seven
 * columns with the domain and objective filled down, and a value sheet the answer column's {@code x14}
 * validation points at.
 *
 * <p>Cells are inline strings, so each workbook is written from its rows alone. The column letters
 * are fixed — domain A, objective B, control C, contact D, KPI E, answer F, comment G — with the
 * header row on row 6 and the items from row 7.
 */
final class ChecklistWorkbooks {

    static final String MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    static final String REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    static final String PACKAGE_REL = "http://schemas.openxmlformats.org/package/2006/relationships";

    static final int FIRST_ITEM_ROW = 7;

    /** One line of the checklist; a blank domain or objective is "same as above". */
    record Line(String domain, String objective, String control, String contact, String kpi) {}

    /** Three invented controls in two domains. */
    static final List<Line> FIRST = List.of(
            new Line("Identity", "1. Accounts are personal", "Every account belongs to one named person.",
                    "Security officer", ""),
            new Line("", "", "Shared accounts are disabled.", "Security officer", "No shared account in the directory"),
            new Line("Supply chain", "2. Dependencies are known", "Every build publishes an SBOM.", "Development lead",
                    "SBOM on every release"));

    /**
     * The next revision of {@link #FIRST}: the first control unchanged, the second reworded, the third
     * with a new KPI, and a fourth added.
     */
    static final List<Line> SECOND = List.of(
            FIRST.get(0),
            new Line("", "", "Shared and generic accounts are disabled.", "Security officer",
                    "No shared account in the directory"),
            new Line("Supply chain", "2. Dependencies are known", "Every build publishes an SBOM.", "Development lead",
                    "SBOM on every release, kept a year"),
            new Line("", "", "Dependencies are pinned by digest.", "Development lead", ""));

    private ChecklistWorkbooks() {}

    static byte[] of(List<Line> lines) {
        Map<String, String> parts = new LinkedHashMap<>();
        parts.put("[Content_Types].xml", """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\
                <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\
                <Default Extension="xml" ContentType="application/xml"/>\
                <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>\
                <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\
                <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\
                <Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\
                </Types>""");
        parts.put("_rels/.rels", """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Relationships xmlns="%s">\
                <Relationship Id="rId1" Type="%s/officeDocument" Target="xl/workbook.xml"/>\
                </Relationships>""".formatted(PACKAGE_REL, REL));
        parts.put("xl/workbook.xml", """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <workbook xmlns="%s" xmlns:r="%s"><sheets>\
                <sheet name="Instructions" sheetId="1" r:id="rId1"/>\
                <sheet name="Checklist" sheetId="2" r:id="rId2"/>\
                <sheet name="Values" sheetId="3" r:id="rId3"/>\
                </sheets><calcPr calcId="191029"/></workbook>""".formatted(MAIN, REL));
        parts.put("xl/_rels/workbook.xml.rels", """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Relationships xmlns="%1$s">\
                <Relationship Id="rId1" Type="%2$s/worksheet" Target="worksheets/sheet1.xml"/>\
                <Relationship Id="rId2" Type="%2$s/worksheet" Target="worksheets/sheet2.xml"/>\
                <Relationship Id="rId3" Type="%2$s/worksheet" Target="worksheets/sheet3.xml"/>\
                </Relationships>""".formatted(PACKAGE_REL, REL));
        parts.put("xl/worksheets/sheet1.xml", sheet(row(1, text("A1", "Read every line and answer it.")), ""));
        parts.put("xl/worksheets/sheet2.xml", sheet(checklistRows(lines), """
                <mergeCells count="1"><mergeCell ref="A1:G1"/></mergeCells>\
                <extLst><ext uri="{CCE6A557-97BC-4b89-ADB6-D9C93CAAB3DF}" \
                xmlns:x14="http://schemas.microsoft.com/office/spreadsheetml/2009/9/main">\
                <x14:dataValidations count="1" xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">\
                <x14:dataValidation type="list" allowBlank="1" showInputMessage="1" showErrorMessage="1">\
                <x14:formula1><xm:f>Values!$A$1:$A$2</xm:f></x14:formula1><xm:sqref>F%d:F%d</xm:sqref>\
                </x14:dataValidation></x14:dataValidations></ext></extLst>"""
                .formatted(FIRST_ITEM_ROW, FIRST_ITEM_ROW + lines.size() - 1)));
        parts.put("xl/worksheets/sheet3.xml", sheet(row(1, text("A1", "Done")) + row(2, text("A2", "Not done")), ""));

        Map<String, byte[]> entries = new LinkedHashMap<>();
        parts.forEach((name, content) -> entries.put(name, content.getBytes(StandardCharsets.UTF_8)));
        return zip(entries);
    }

    private static String checklistRows(List<Line> lines) {
        StringBuilder rows = new StringBuilder()
                .append(row(1, text("A1", "Release checklist")))
                .append("<row r=\"2\">").append(text("A2", "Date")).append("<c r=\"B2\"><f>TODAY()</f><v>46293</v></c></row>")
                .append(row(3, text("A3", "Product")))
                .append(row(4, text("A4", "Author")))
                .append(row(6, text("A6", "Domain") + text("B6", "Objective") + text("C6", "Control") + text("D6", "Contact")
                        + text("E6", "KPI") + text("F6", "Answer") + text("G6", "Comment (required when negative)")));
        for (int i = 0; i < lines.size(); i++) {
            int number = FIRST_ITEM_ROW + i;
            Line line = lines.get(i);
            List<String> cells = new ArrayList<>();
            String[] values = {line.domain(), line.objective(), line.control(), line.contact(), line.kpi()};
            for (int column = 0; column < values.length; column++) {
                if (!values[column].isEmpty()) {
                    cells.add(text((char) ('A' + column) + String.valueOf(number), values[column]));
                }
            }
            rows.append(row(number, String.join("", cells)));
        }
        return rows.toString();
    }

    private static String row(int number, String cells) {
        return "<row r=\"" + number + "\">" + cells + "</row>";
    }

    private static String text(String reference, String value) {
        return "<c r=\"" + reference + "\" t=\"inlineStr\"><is><t>" + value.replace("&", "&amp;").replace("<", "&lt;")
                + "</t></is></c>";
    }

    private static String sheet(String rows, String after) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<worksheet xmlns=\"" + MAIN + "\" xmlns:r=\""
                + REL + "\"><sheetData>" + rows + "</sheetData>" + after + "</worksheet>";
    }

    static byte[] zip(Map<String, byte[]> entries) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        } catch (IOException impossible) {
            throw new UncheckedIOException(impossible);
        }
        return bytes.toByteArray();
    }
}
