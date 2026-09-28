package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("the template workbook reader")
class WorkbookReaderTest {

    private static final long TEN_MB = 10L * 1024 * 1024;

    private static CellRef at(String reference) {
        return CellRef.parse(reference).orElseThrow();
    }

    private static void refused(ThrowingCallable read, String words) {
        assertThatThrownBy(read).isInstanceOf(InvalidTemplateException.class).hasMessageContaining(words);
    }

    @Nested
    @DisplayName("reads")
    class Reads {

        private final Workbook workbook = new XlsxFixture().read();
        private final Sheet checklist = workbook.sheet("Checklist").orElseThrow();

        @Test
        @DisplayName("the worksheets in the workbook's order, and the digest of the file as received")
        void sheets() {
            byte[] file = new XlsxFixture().bytes();

            Workbook read = Workbook.read(file, TEN_MB);

            assertThat(read.sheets()).extracting(Sheet::name).containsExactly("Instructions", "Checklist", "Values");
            assertThat(read.sha256()).isEqualTo(Digests.sha256Hex(file));
        }

        @Test
        @DisplayName("shared strings, their rich-text runs joined and the phonetic reading left out, and inline strings")
        void strings() {
            assertThat(checklist.text(at("C7"))).isEqualTo("Every account belongs to one named person.");
            assertThat(checklist.text(at("C9"))).isEqualTo("An idle session ends after fifteen minutes.");
            assertThat(checklist.text(at("C11"))).isEqualTo("Critical vulnerabilities are fixed within 30 days & tracked.");
        }

        @Test
        @DisplayName("a formula as its expression and its cached value, never evaluated")
        void formula() {
            assertThat(checklist.value(at("B2"))).contains(new CellValue.Formula("TODAY()", Optional.of("46293")));
        }

        @Test
        @DisplayName("a styled empty cell as blank")
        void styledBlank() {
            assertThat(checklist.value(at("B3"))).isEmpty();
            assertThat(checklist.blank(at("A8"))).isTrue();
        }

        @Test
        @DisplayName("the list validation kept in the x14 extension, which mainstream readers drop")
        void extensionValidation() {
            assertThat(checklist.validations()).singleElement().satisfies(validation -> {
                assertThat(validation.fromExtension()).isTrue();
                assertThat(validation.source()).isEqualTo("Values!$A$1:$A$2");
                assertThat(validation.ranges()).containsExactly(CellRange.parse("F7:F11").orElseThrow());
                assertThat(workbook.listValues(validation, checklist)).containsExactly("Done", "Not done");
            });
        }

        @Test
        @DisplayName("the sheet's own list validation, a literal list, and one through a defined name")
        void sheetValidation() {
            String validations = "<dataValidations count=\"2\">"
                    + "<dataValidation type=\"list\" sqref=\"F7:F11\"><formula1>AnswerWords</formula1></dataValidation>"
                    + "<dataValidation type=\"list\" sqref=\"H7\"><formula1>\"Yes,No,Yes\"</formula1></dataValidation>"
                    + "<dataValidation type=\"whole\" sqref=\"I7\"><formula1>1</formula1></dataValidation>"
                    + "</dataValidations>";
            Workbook read = new XlsxFixture()
                    .put("xl/worksheets/sheet2.xml", XlsxFixture.sheet("<row r=\"7\"><c r=\"C7\" t=\"s\"><v>14</v></c></row>",
                            validations))
                    .read();
            Sheet sheet = read.sheet("Checklist").orElseThrow();

            assertThat(sheet.validations()).hasSize(2).noneMatch(ListValidation::fromExtension);
            assertThat(read.listValues(sheet.validations().get(0), sheet)).containsExactly("Done", "Not done");
            assertThat(read.listValues(sheet.validations().get(1), sheet)).containsExactly("Yes", "No");
        }

        @Test
        @DisplayName("a list computed by a formula as no words, rather than an evaluation")
        void computedList() {
            ListValidation computed = new ListValidation(List.of(), "INDIRECT(\"Values!A1:A2\")", false);

            assertThat(workbook.listValues(computed, checklist)).isEmpty();
        }

        @Test
        @DisplayName("the merged title, and only workbook-scoped defined names")
        void mergesAndNames() {
            assertThat(checklist.merged()).containsExactly(CellRange.parse("A1:G1").orElseThrow());
            assertThat(workbook.definedNames()).containsOnlyKeys("AnswerWords");
        }

        @Test
        @DisplayName("cells placed by their order alone, as the format allows")
        void impliedReferences() {
            Workbook read = new XlsxFixture()
                    .put("xl/worksheets/sheet1.xml", XlsxFixture.sheet(
                            "<row r=\"3\"><c t=\"s\"><v>2</v></c><c t=\"s\"><v>3</v></c></row><row><c><v>7</v></c></row>", ""))
                    .read();
            Sheet sheet = read.sheets().getFirst();

            assertThat(sheet.text(at("A3"))).isEqualTo("Date");
            assertThat(sheet.text(at("B3"))).isEqualTo("Product");
            assertThat(sheet.value(at("A4"))).contains(new CellValue.Number("7"));
        }

        @Test
        @DisplayName("booleans and errors as what they are")
        void otherTypes() {
            Workbook read = new XlsxFixture()
                    .put("xl/worksheets/sheet1.xml", XlsxFixture.sheet(
                            "<row r=\"1\"><c r=\"A1\" t=\"b\"><v>1</v></c><c r=\"B1\" t=\"e\"><v>#N/A</v></c></row>", ""))
                    .read();

            assertThat(read.sheets().getFirst().value(at("A1"))).contains(new CellValue.Bool(true));
            assertThat(read.sheets().getFirst().value(at("B1"))).contains(new CellValue.Error("#N/A"));
        }
    }

    @Nested
    @DisplayName("refuses what is not an .xlsx without macros")
    class Formats {

        @Test
        @DisplayName("an empty body, and one past the ceiling")
        void size() {
            refused(() -> Workbook.read(new byte[0], TEN_MB), "empty");
            refused(() -> Workbook.read(new XlsxFixture().bytes(), 100), "larger than the 100 bytes");
        }

        @Test
        @DisplayName("a legacy .xls, or an encrypted workbook, by the compound file's signature")
        void legacy() {
            byte[] compound = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A, (byte) 0xE1, 0, 0};

            refused(() -> Workbook.read(compound, TEN_MB), "legacy .xls");
        }

        @Test
        @DisplayName("anything that is not a zip")
        void notAZip() {
            refused(() -> Workbook.read("a,b\n1,2\n".getBytes(StandardCharsets.UTF_8), TEN_MB), "not an .xlsx");
        }

        @Test
        @DisplayName("an OpenDocument spreadsheet")
        void openDocument() {
            byte[] ods = XlsxFixture.zip(Map.of("mimetype",
                    "application/vnd.oasis.opendocument.spreadsheet".getBytes(StandardCharsets.US_ASCII)));

            refused(() -> Workbook.read(ods, TEN_MB), "OpenDocument");
        }

        @Test
        @DisplayName("a macro-enabled workbook, by its main part's content type")
        void macroEnabled() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put("[Content_Types].xml", fixture.parts.get("[Content_Types].xml")
                    .replace(XlsxFixture.SHEET_TYPE, "application/vnd.ms-excel.sheet.macroEnabled.main+xml"));

            refused(fixture::read, "carries macros");
        }

        @Test
        @DisplayName("a VBA project, whatever the main part claims")
        void vbaProject() {
            refused(() -> new XlsxFixture().put("xl/vbaProject.bin", "not really").read(), "carries macros");
        }

        @Test
        @DisplayName("an Excel 4 macro sheet")
        void macroSheet() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put("[Content_Types].xml", fixture.parts.get("[Content_Types].xml").replace("</Types>",
                    "<Override PartName=\"/xl/macrosheets/sheet1.xml\" ContentType=\"application/vnd.ms-excel.macrosheet+xml\"/></Types>"));
            fixture.put("xl/macrosheets/sheet1.xml", XlsxFixture.sheet("", ""));

            refused(fixture::read, "carries macros");
        }

        @Test
        @DisplayName("a binary workbook")
        void binary() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put("[Content_Types].xml", fixture.parts.get("[Content_Types].xml")
                    .replace(XlsxFixture.SHEET_TYPE, "application/vnd.ms-excel.sheet.binary.macroEnabled.main"));

            refused(fixture::read, "binary workbook");
        }

        @Test
        @DisplayName("a package whose main part is not a spreadsheet")
        void notASpreadsheet() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put("[Content_Types].xml", fixture.parts.get("[Content_Types].xml").replace(XlsxFixture.SHEET_TYPE,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"));

            refused(fixture::read, "not a spreadsheet");
        }

        @Test
        @DisplayName("a package without content types, relationships or a workbook part")
        void missingParts() {
            refused(() -> new XlsxFixture().remove("[Content_Types].xml").read(), "no content types");
            refused(() -> new XlsxFixture().remove("_rels/.rels").read(), "no relationships part");
            refused(() -> new XlsxFixture().put("_rels/.rels", "<Relationships xmlns=\"" + XlsxFixture.PACKAGE_REL + "\"/>")
                    .read(), "no workbook part");
            refused(() -> new XlsxFixture().remove("xl/worksheets/sheet2.xml").read(), "does not hold");
        }

        @Test
        @DisplayName("a relationship pointing outside the package, in any part")
        void externalTarget() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put("xl/worksheets/_rels/sheet2.xml.rels", fixture.parts.get("xl/worksheets/_rels/sheet2.xml.rels")
                    .replace("</Relationships>", "<Relationship Id=\"rId9\" Type=\"" + XlsxFixture.REL
                            + "/hyperlink\" Target=\"https://example.invalid/policy\" TargetMode=\"External\"/></Relationships>"));

            refused(fixture::read, "points outside the package");
        }
    }

    @Nested
    @DisplayName("reads XML without resolving anything")
    class Xml {

        @Test
        @DisplayName("a DOCTYPE in a part is refused, even one that only names its DTD")
        void doctype() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put("xl/workbook.xml", fixture.parts.get("xl/workbook.xml").replace("standalone=\"yes\"?>",
                    "standalone=\"yes\"?><!DOCTYPE workbook SYSTEM \"http://example.invalid/workbook.dtd\">"));

            refused(fixture::read, "carries a DOCTYPE declaration");
        }

        @Test
        @DisplayName("an entity is never expanded: an internal subset and a reference to it are refused")
        void entity() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put("xl/sharedStrings.xml", fixture.parts.get("xl/sharedStrings.xml")
                    .replace("standalone=\"yes\"?>", "standalone=\"yes\"?><!DOCTYPE sst [<!ENTITY secret SYSTEM "
                            + "\"file:///etc/passwd\">]>")
                    .replace("<t>Done</t>", "<t>&secret;</t>"));

            refused(fixture::read, "Part xl/sharedstrings.xml");
        }

        @Test
        @DisplayName("an undeclared entity in a part with no DOCTYPE is refused")
        void undeclaredEntity() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put("xl/sharedStrings.xml", fixture.parts.get("xl/sharedStrings.xml").replace("<t>Done</t>", "<t>&secret;</t>"));

            assertThatThrownBy(fixture::read).isInstanceOf(InvalidTemplateException.class);
        }

        @Test
        @DisplayName("malformed XML says which part")
        void malformed() {
            refused(() -> new XlsxFixture().put("xl/workbook.xml", "<workbook><sheets></workbook>").read(),
                    "Part xl/workbook.xml is not well-formed XML");
        }

        @Test
        @DisplayName("a shared string index the table does not hold")
        void sharedIndex() {
            refused(() -> new XlsxFixture().put("xl/worksheets/sheet1.xml",
                    XlsxFixture.sheet("<row r=\"1\"><c r=\"A1\" t=\"s\"><v>999</v></c></row>", "")).read(),
                    "refers to a shared string");
        }

        @Test
        @DisplayName("a cell's text longer than a spreadsheet cell holds")
        void cellText() {
            String longText = "x".repeat(WorkbookReader.MAX_CELL_TEXT + 1);
            refused(() -> new XlsxFixture().put("xl/worksheets/sheet1.xml",
                    XlsxFixture.sheet("<row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>" + longText + "</t></is></c></row>", ""))
                    .read(), "more than " + WorkbookReader.MAX_CELL_TEXT + " characters");
        }
    }

    @Nested
    @DisplayName("holds the zip to its guards, counted as the bytes come out")
    class Guards {

        private static final Workbook.Limits DEFAULT = Workbook.Limits.DEFAULT;

        private static Workbook.Limits limits(int entries, long entryBytes, long totalBytes, long elements, int sheets,
                int cells, int strings) {
            return new Workbook.Limits(entries, entryBytes, totalBytes, DEFAULT.maxRatio(), DEFAULT.ratioGraceBytes(),
                    elements, sheets, cells, strings);
        }

        /** The fixture's parts, then extra entries — stored, so that no ratio is involved. */
        private static byte[] withStored(Map<String, byte[]> extra) throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
                for (Map.Entry<String, String> part : new XlsxFixture().parts.entrySet()) {
                    zip.putNextEntry(new ZipEntry(part.getKey()));
                    zip.write(part.getValue().getBytes(StandardCharsets.UTF_8));
                    zip.closeEntry();
                }
                for (Map.Entry<String, byte[]> entry : extra.entrySet()) {
                    zip.putNextEntry(XlsxFixture.stored(entry.getKey(), entry.getValue()));
                    zip.write(entry.getValue());
                    zip.closeEntry();
                }
            }
            return bytes.toByteArray();
        }

        private static byte[] noise(int size) {
            byte[] bytes = new byte[size];
            new Random(42).nextBytes(bytes);
            return bytes;
        }

        @Test
        @DisplayName("more entries than a workbook has")
        void entries() {
            XlsxFixture fixture = new XlsxFixture();
            for (int i = 0; fixture.parts.size() <= DEFAULT.maxEntries(); i++) {
                fixture.put("xl/media/image" + i + ".png", "");
            }

            refused(fixture::read, "more than " + DEFAULT.maxEntries() + " entries");
        }

        @Test
        @DisplayName("an entry that inflates a hundred times its size, as a zip bomb does")
        void bomb() {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            new XlsxFixture().parts.forEach((name, content) -> entries.put(name, content.getBytes(StandardCharsets.UTF_8)));
            entries.put("xl/media/image1.png", new byte[5 * 1024 * 1024]);

            refused(() -> Workbook.read(XlsxFixture.zip(entries), TEN_MB), "inflates more than 100 times");
        }

        @Test
        @DisplayName("a small part compressing far better than a hundred to one is no bomb")
        void grace() {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            new XlsxFixture().parts.forEach((name, content) -> entries.put(name, content.getBytes(StandardCharsets.UTF_8)));
            entries.put("xl/printerSettings/printerSettings1.bin", new byte[(int) DEFAULT.ratioGraceBytes()]);

            assertThat(Workbook.read(XlsxFixture.zip(entries), TEN_MB).sheets()).hasSize(3);
        }

        @Test
        @DisplayName("one entry past its ceiling, whatever its header says")
        void entryBytes() throws IOException {
            byte[] file = withStored(Map.of("xl/media/image1.png", noise(64 * 1024)));

            refused(() -> Workbook.read(file, TEN_MB, limits(200, 32 * 1024, TEN_MB, 5_000_000, 64, 1_000, 1_000)),
                    "Entry xl/media/image1.png inflates past 32768 bytes");
        }

        @Test
        @DisplayName("every entry together past the ceiling")
        void totalBytes() throws IOException {
            byte[] file = withStored(Map.of("xl/media/a.png", noise(40 * 1024), "xl/media/b.png", noise(40 * 1024)));

            refused(() -> Workbook.read(file, TEN_MB, limits(200, 64 * 1024, 64 * 1024, 5_000_000, 64, 1_000, 1_000)),
                    "The workbook inflates past 65536 bytes");
        }

        @Test
        @DisplayName("an archive inside the archive, by its name")
        void nestedByName() {
            refused(() -> new XlsxFixture().put("xl/embeddings/Other_Workbook.xlsx", "whatever").read(),
                    "archive inside the workbook");
        }

        @Test
        @DisplayName("an archive inside the archive, by its first bytes, whatever its name")
        void nestedByContent() {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            new XlsxFixture().parts.forEach((name, content) -> entries.put(name, content.getBytes(StandardCharsets.UTF_8)));
            entries.put("xl/media/image1.png", XlsxFixture.zip(Map.of("inner.txt", new byte[10])));

            refused(() -> Workbook.read(XlsxFixture.zip(entries), TEN_MB), "Entry xl/media/image1.png is an archive");
        }

        @Test
        @DisplayName("a part the archive holds twice, which two programs would each read differently")
        void duplicate() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put("xl/Workbook.xml", fixture.parts.get("xl/workbook.xml"));

            refused(fixture::read, "twice");
        }

        @Test
        @DisplayName("more sheets, cells, shared strings or XML elements than the limits hold")
        void counts() {
            byte[] file = new XlsxFixture().bytes();

            refused(() -> Workbook.read(file, TEN_MB, limits(200, TEN_MB, TEN_MB, 5_000_000, 2, 1_000, 1_000)),
                    "more than 2 sheets");
            refused(() -> Workbook.read(file, TEN_MB, limits(200, TEN_MB, TEN_MB, 5_000_000, 64, 20, 1_000)),
                    "more than 20 cells");
            refused(() -> Workbook.read(file, TEN_MB, limits(200, TEN_MB, TEN_MB, 5_000_000, 64, 1_000, 10)),
                    "more than 10 entries");
            refused(() -> Workbook.read(file, TEN_MB, limits(200, TEN_MB, TEN_MB, 50, 64, 1_000, 1_000)),
                    "The workbook holds more than 50 XML elements");
        }

        @Test
        @DisplayName("the default limits read the fixture")
        void defaults() {
            assertThat(Workbook.read(new XlsxFixture().bytes(), TEN_MB, DEFAULT).sheets()).hasSize(3);
        }
    }
}
