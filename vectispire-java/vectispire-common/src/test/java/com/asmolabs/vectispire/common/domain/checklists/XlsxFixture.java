package com.asmolabs.vectispire.common.domain.checklists;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * A template workbook written part by part, from invented controls — never a real template, whose
 * content is its organisation's (decision 0032). Shaped like the first one: instructions, the
 * checklist with a merged title, a date formula, product and author cells, a header row and seven
 * columns filled down, and a value sheet the answer column's {@code x14} validation points at; one
 * cell carries a comment.
 *
 * <p>Mutable on purpose: a test replaces one part to see one guard answer.
 */
final class XlsxFixture {

    static final String MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    static final String REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    static final String PACKAGE_REL = "http://schemas.openxmlformats.org/package/2006/relationships";
    static final String SHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";

    /** The shared strings, in the order the sheets refer to them by index. */
    static final List<String> STRINGS = List.of(
            "Read every line and answer it.", // 0
            "Release checklist", // 1
            "Date", // 2
            "Product", // 3
            "Author", // 4
            "Domain", // 5
            "Objective", // 6
            "Control", // 7
            "Contact", // 8
            "KPI", // 9
            "Answer", // 10
            "Comment (required when the answer is negative)", // 11
            "Identity", // 12
            "1. Accounts are personal", // 13
            "Every account belongs to one named person.", // 14
            "Security officer", // 15
            "Shared accounts are disabled.", // 16
            "No shared account in the directory", // 17
            "2. Sessions expire", // 18
            "Development lead", // 19 (index 20 is the rich-text string below)
            "Supply chain", // 21
            "3. Dependencies are known", // 22
            "Every build publishes an SBOM.", // 23
            "SBOM on every release", // 24
            "Done", // 25
            "Not done"); // 26

    final Map<String, String> parts = new LinkedHashMap<>();

    XlsxFixture() {
        parts.put("[Content_Types].xml", """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\
                <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\
                <Default Extension="xml" ContentType="application/xml"/>\
                <Default Extension="vml" ContentType="application/vnd.openxmlformats-officedocument.vmlDrawing"/>\
                <Override PartName="/xl/workbook.xml" ContentType="%s"/>\
                <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\
                <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\
                <Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>\
                <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>\
                <Override PartName="/xl/comments1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml"/>\
                </Types>""".formatted(SHEET_TYPE));
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
                </sheets><definedNames><definedName name="AnswerWords">Values!$A$1:$A$2</definedName>\
                <definedName name="_xlnm.Print_Area" localSheetId="1">Checklist!$A$1:$G$11</definedName></definedNames>\
                <calcPr calcId="191029"/></workbook>""".formatted(MAIN, REL));
        parts.put("xl/_rels/workbook.xml.rels", """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Relationships xmlns="%1$s">\
                <Relationship Id="rId1" Type="%2$s/worksheet" Target="worksheets/sheet1.xml"/>\
                <Relationship Id="rId2" Type="%2$s/worksheet" Target="worksheets/sheet2.xml"/>\
                <Relationship Id="rId3" Type="%2$s/worksheet" Target="/xl/worksheets/sheet3.xml"/>\
                <Relationship Id="rId4" Type="%2$s/sharedStrings" Target="sharedStrings.xml"/>\
                </Relationships>""".formatted(PACKAGE_REL, REL));
        parts.put("xl/sharedStrings.xml", sharedStrings());
        parts.put("xl/worksheets/sheet1.xml", sheet("<row r=\"1\"><c r=\"A1\" t=\"s\"><v>0</v></c></row>", ""));
        parts.put("xl/worksheets/sheet2.xml", sheet(checklistRows(), """
                <mergeCells count="1"><mergeCell ref="A1:G1"/></mergeCells>\
                <legacyDrawing r:id="rId2"/>\
                <extLst><ext uri="{CCE6A557-97BC-4b89-ADB6-D9C93CAAB3DF}" \
                xmlns:x14="http://schemas.microsoft.com/office/spreadsheetml/2009/9/main">\
                <x14:dataValidations count="1" xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">\
                <x14:dataValidation type="list" allowBlank="1" showInputMessage="1" showErrorMessage="1">\
                <x14:formula1><xm:f>Values!$A$1:$A$2</xm:f></x14:formula1><xm:sqref>F7:F11</xm:sqref>\
                </x14:dataValidation></x14:dataValidations></ext></extLst>"""));
        parts.put("xl/worksheets/_rels/sheet2.xml.rels", """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <Relationships xmlns="%1$s">\
                <Relationship Id="rId1" Type="%2$s/comments" Target="../comments1.xml"/>\
                <Relationship Id="rId2" Type="%2$s/vmlDrawing" Target="../drawings/vmlDrawing1.vml"/>\
                </Relationships>""".formatted(PACKAGE_REL, REL));
        parts.put("xl/comments1.xml", """
                <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <comments xmlns="%s"><authors><author>Template author</author></authors><commentList>\
                <comment ref="C11" authorId="0"><text><r><t>Counted from the advisory's publication.</t></r></text></comment>\
                </commentList></comments>""".formatted(MAIN));
        parts.put("xl/drawings/vmlDrawing1.vml", "<xml xmlns:v=\"urn:schemas-microsoft-com:vml\"><v:shape/></xml>");
        parts.put("xl/worksheets/sheet3.xml", sheet("<row r=\"1\"><c r=\"A1\" t=\"s\"><v>25</v></c></row>"
                + "<row r=\"2\"><c r=\"A2\" t=\"s\"><v>26</v></c></row>", ""));
    }

    private static String checklistRows() {
        return row(1, s("A1", 1))
                + "<row r=\"2\">" + s("A2", 2) + "<c r=\"B2\" s=\"3\"><f>TODAY()</f><v>46293</v></c></row>"
                + row(3, s("A3", 3) + "<c r=\"B3\" s=\"1\"/>")
                + row(4, s("A4", 4))
                + row(6, s("A6", 5) + s("B6", 6) + s("C6", 7) + s("D6", 8) + s("E6", 9) + s("F6", 10) + s("G6", 11))
                + row(7, s("A7", 12) + s("B7", 13) + s("C7", 14) + s("D7", 15))
                + row(8, "<c r=\"A8\" s=\"1\"/>" + s("C8", 16) + s("D8", 15) + s("E8", 17))
                + row(9, s("B9", 18) + s("C9", 20) + s("D9", 19))
                + row(10, s("A10", 21) + s("B10", 22) + s("C10", 23) + s("D10", 19) + s("E10", 24))
                + row(11, "<c r=\"C11\" t=\"inlineStr\"><is><t>Critical vulnerabilities are fixed within 30 days &amp; "
                        + "tracked.</t></is></c>" + s("D11", 15));
    }

    private static String row(int number, String cells) {
        return "<row r=\"" + number + "\">" + cells + "</row>";
    }

    private static String s(String reference, int index) {
        return "<c r=\"" + reference + "\" t=\"s\"><v>" + index + "</v></c>";
    }

    /** String 20 is written in two runs, with a phonetic reading that is not its text. */
    private static String sharedStrings() {
        StringBuilder xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<sst xmlns=\""
                + MAIN + "\" count=\"" + (STRINGS.size() + 1) + "\">");
        for (int i = 0; i < STRINGS.size(); i++) {
            if (i == 20) {
                xml.append("<si><r><rPr><b/></rPr><t>An idle session</t></r><r><t xml:space=\"preserve\"> ends after "
                        + "fifteen minutes.</t></r><rPh sb=\"0\" eb=\"1\"><t>PHONETIC</t></rPh></si>");
            }
            xml.append("<si><t>").append(STRINGS.get(i)).append("</t></si>");
        }
        return xml.append("</sst>").toString();
    }

    static String sheet(String rows, String after) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<worksheet xmlns=\"" + MAIN + "\" xmlns:r=\""
                + REL + "\"><sheetData>" + rows + "</sheetData>" + after + "</worksheet>";
    }

    XlsxFixture put(String part, String content) {
        parts.put(part, content);
        return this;
    }

    XlsxFixture remove(String part) {
        parts.remove(part);
        return this;
    }

    byte[] bytes() {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        parts.forEach((name, content) -> entries.put(name, content.getBytes(StandardCharsets.UTF_8)));
        return zip(entries);
    }

    Workbook read() {
        return Workbook.read(bytes(), 10L * 1024 * 1024);
    }

    /** Deflated entries, in the order given. */
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

    /** One entry stored rather than deflated: its bytes are counted without any inflation ratio. */
    static ZipEntry stored(String name, byte[] content) {
        ZipEntry entry = new ZipEntry(name);
        entry.setMethod(ZipEntry.STORED);
        entry.setSize(content.length);
        entry.setCompressedSize(content.length);
        CRC32 crc = new CRC32();
        crc.update(content);
        entry.setCrc(crc.getValue());
        return entry;
    }
}
