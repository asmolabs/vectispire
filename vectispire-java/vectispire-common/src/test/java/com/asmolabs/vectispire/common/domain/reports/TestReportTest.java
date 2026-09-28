package com.asmolabs.vectispire.common.domain.reports;

import static com.asmolabs.vectispire.common.domain.reports.CoverageReportTest.sample;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The JUnit reader, on invented reports shaped as Surefire and pytest write them, one document or a
 * zip of them — and the zip's guards, on archives built here to break them.
 */
@DisplayName("reading a JUnit test report")
class TestReportTest {

    private static final long CAP = 32L * 1024 * 1024;

    private static TestReport xml(String document) {
        return TestReport.read(TestReportFormat.JUNIT_XML, document.getBytes(StandardCharsets.UTF_8), CAP);
    }

    static byte[] zip(Map<String, byte[]> entries) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            zip.setLevel(Deflater.BEST_COMPRESSION);
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

    /** An entry whose inflated size is {@code size} spaces around a valid suite: small once deflated. */
    private static void bomb(ZipOutputStream zip, String name, long size) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write("<testsuite name=\"s\">".getBytes(StandardCharsets.UTF_8));
        byte[] spaces = new byte[1 << 20];
        java.util.Arrays.fill(spaces, (byte) ' ');
        for (long written = 0; written < size; written += spaces.length) {
            zip.write(spaces);
        }
        zip.write("<testcase name=\"t\"/></testsuite>".getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    @Nested
    @DisplayName("one document")
    class OneDocument {

        @Test
        @DisplayName("counts each case into its suite: a failure, an error, a skip, and a flaky pass as a pass")
        void surefire() {
            TestReport report = TestReport.read(TestReportFormat.JUNIT_XML,
                    sample("TEST-com.example.invoicing.InvoiceTest.xml"), CAP);

            assertThat(report.suites()).containsExactly(
                    new TestReport.Suite("com.example.invoicing.InvoiceTest", 5, 1, 1, 1));
            assertThat(report.documents()).isEqualTo(1);
            assertThat(report.format()).isEqualTo(TestReportFormat.JUNIT_XML);
        }

        @Test
        @DisplayName("counts the cases, not the summary: pytest's tests=\"7\" over three cases is three")
        void casesOverAttributes() {
            TestReport report = TestReport.read(TestReportFormat.JUNIT_XML, sample("pytest.xml"), CAP);

            assertThat(report.suites()).containsExactly(new TestReport.Suite("pytest", 3, 1, 0, 0));
            assertThat(report.tests()).isEqualTo(3);
            assertThat(report.failures()).isEqualTo(1);
        }

        @Test
        @DisplayName("a nested suite keeps its own cases; a container of suites is not a suite")
        void nested() {
            TestReport report = xml("<testsuites><testsuite name=\"outer\"><testcase name=\"a\"/>"
                    + "<testsuite name=\"inner\"><testcase name=\"b\"><error/></testcase><testcase name=\"c\"/></testsuite>"
                    + "</testsuite><testsuite name=\"container\"><testsuite name=\"leaf\"><testcase name=\"d\"><skipped/>"
                    + "</testcase></testsuite></testsuite></testsuites>");

            assertThat(report.suites()).containsExactly(
                    new TestReport.Suite("inner", 2, 0, 1, 0),
                    new TestReport.Suite("outer", 1, 0, 0, 0),
                    new TestReport.Suite("leaf", 1, 0, 0, 1));
        }

        @Test
        @DisplayName("a case is counted once, by its worst outcome, from its own children only")
        void outcomes() {
            TestReport report = xml("<testsuite name=\"s\">"
                    + "<testcase name=\"a\"><error/><failure/></testcase>"
                    + "<testcase name=\"b\"><skipped/><failure/></testcase>"
                    + "<testcase name=\"c\"><system-out><failure/></system-out></testcase>"
                    + "</testsuite>");

            assertThat(report.suites()).containsExactly(new TestReport.Suite("s", 3, 1, 1, 0));
        }

        @Test
        @DisplayName("a report with no test case is refused: it is not a passing suite")
        void empty() {
            assertThatThrownBy(() -> xml("<testsuites/>"))
                    .isInstanceOf(InvalidReportException.class)
                    .hasMessageContaining("holds no test case");
            assertThatThrownBy(() -> xml("<testsuite name=\"s\" tests=\"12\" failures=\"0\"/>"))
                    .hasMessageContaining("holds no test case");
        }

        @Test
        @DisplayName("not JUnit, an unnamed suite, a case outside a suite, an entity, an internal subset: refused")
        void refused() {
            assertThatThrownBy(() -> TestReport.read(TestReportFormat.JUNIT_XML, sample("jacoco.xml"), CAP))
                    .hasMessageContaining("is it a JUnit XML report");
            assertThatThrownBy(() -> xml("<testsuite><testcase name=\"a\"/></testsuite>"))
                    .hasMessageContaining("without a name");
            assertThatThrownBy(() -> xml("<testsuites><testcase name=\"a\"/></testsuites>"))
                    .hasMessageContaining("outside any testsuite");
            assertThatThrownBy(() -> xml("<?xml version=\"1.0\"?><!DOCTYPE testsuite [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
                            + "<testsuite name=\"&x;\"><testcase name=\"a\"/></testsuite>"))
                    .hasMessageContaining("internal DTD subset");
            // Without an XML declaration the JDK hands the DOCTYPE back damaged; the entity is still
            // undefined, and the document is refused at the reference.
            assertThatThrownBy(() -> xml("<!DOCTYPE testsuite [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
                            + "<testsuite name=\"&x;\"><testcase name=\"a\"/></testsuite>"))
                    .isInstanceOf(InvalidReportException.class)
                    .hasMessageContaining("not well-formed");
            assertThatThrownBy(() -> xml("<testsuite name=\"s\"><testcase name=\"a\">"))
                    .hasMessageContaining("not well-formed");
        }

        @Test
        @DisplayName("a suite's name is clipped to its column")
        void longName() {
            TestReport report = xml("<testsuite name=\"" + "a".repeat(600) + "\"><testcase name=\"t\"/></testsuite>");

            assertThat(report.suites().getFirst().name()).hasSize(TestReport.MAX_SUITE_NAME);
        }
    }

    @Nested
    @DisplayName("a zip of documents")
    class Zipped {

        @Test
        @DisplayName("reads every .xml entry, and passes over Surefire's .txt beside them")
        void surefireDirectory() {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            entries.put("surefire-reports/", new byte[0]);
            entries.put("surefire-reports/TEST-com.example.invoicing.InvoiceTest.xml",
                    sample("TEST-com.example.invoicing.InvoiceTest.xml"));
            entries.put("surefire-reports/com.example.invoicing.InvoiceTest.txt",
                    "Tests run: 5, Failures: 1".getBytes(StandardCharsets.UTF_8));
            entries.put("surefire-reports/TEST-com.example.tax.RateTest.xml", sample("TEST-com.example.tax.RateTest.xml"));

            TestReport report = TestReport.read(TestReportFormat.JUNIT_ZIP, zip(entries), CAP);

            assertThat(report.documents()).isEqualTo(2);
            assertThat(report.suites()).extracting(TestReport.Suite::name)
                    .containsExactly("com.example.invoicing.InvoiceTest", "com.example.tax.RateTest");
            assertThat(report.tests()).isEqualTo(7);
        }

        @Test
        @DisplayName("an entry that is not JUnit refuses the archive, naming the entry")
        void oneBadEntry() {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            entries.put("TEST-a.xml", sample("TEST-com.example.tax.RateTest.xml"));
            entries.put("pom.xml", "<project/>".getBytes(StandardCharsets.UTF_8));

            assertThatThrownBy(() -> TestReport.read(TestReportFormat.JUNIT_ZIP, zip(entries), CAP))
                    .hasMessageContaining("Entry pom.xml opens with <project>");
        }

        @Test
        @DisplayName("an archive inside the archive is refused, by name and by content")
        void nested() {
            byte[] inner = zip(Map.of("TEST-a.xml", sample("TEST-com.example.tax.RateTest.xml")));

            assertThatThrownBy(() -> TestReport.read(TestReportFormat.JUNIT_ZIP, zip(Map.of("reports.zip", inner)), CAP))
                    .hasMessageContaining("archive inside the archive");
            assertThatThrownBy(() -> TestReport.read(TestReportFormat.JUNIT_ZIP, zip(Map.of("TEST-b.xml", inner)), CAP))
                    .hasMessageContaining("archive inside the archive");
        }

        @Test
        @DisplayName("an entry inflating past its bound is refused while it inflates — whatever its name")
        void entryBomb() throws IOException {
            for (String name : new String[] {"TEST-bomb.xml", "notes.txt"}) {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
                    zip.setLevel(Deflater.BEST_COMPRESSION);
                    bomb(zip, name, TestReport.MAX_ENTRY_BYTES + 1);
                }
                assertThat(bytes.size()).as("small once deflated").isLessThan(200_000);

                assertThatThrownBy(() -> TestReport.read(TestReportFormat.JUNIT_ZIP, bytes.toByteArray(), CAP))
                        .isInstanceOf(InvalidReportException.class)
                        .hasMessageContaining("inflates past " + TestReport.MAX_ENTRY_BYTES);
            }
        }

        @Test
        @DisplayName("entries each within their bound, together past the archive's, are refused")
        void archiveBomb() throws IOException {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
                zip.setLevel(Deflater.BEST_COMPRESSION);
                long each = TestReport.MAX_ENTRY_BYTES - (2 << 20);
                for (int i = 0; i * each <= TestReport.MAX_INFLATED_BYTES; i++) {
                    bomb(zip, "TEST-" + i + ".xml", each);
                }
            }

            assertThatThrownBy(() -> TestReport.read(TestReportFormat.JUNIT_ZIP, bytes.toByteArray(), CAP))
                    .hasMessageContaining("The zip inflates past " + TestReport.MAX_INFLATED_BYTES);
        }

        @Test
        @DisplayName("more entries than the bound are refused, even empty ones")
        void entries() {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            for (int i = 0; i <= TestReport.MAX_ENTRIES; i++) {
                entries.put("e" + i + ".txt", new byte[0]);
            }

            assertThatThrownBy(() -> TestReport.read(TestReportFormat.JUNIT_ZIP, zip(entries), CAP))
                    .hasMessageContaining("more than " + TestReport.MAX_ENTRIES + " entries");
        }

        @Test
        @DisplayName("a body that is no zip, or a zip with no .xml, is refused")
        void notAZip() {
            assertThatThrownBy(() -> TestReport.read(TestReportFormat.JUNIT_ZIP,
                            sample("TEST-com.example.tax.RateTest.xml"), CAP))
                    .hasMessageContaining("not a zip archive");
            assertThatThrownBy(() -> TestReport.read(TestReportFormat.JUNIT_ZIP,
                            zip(Map.of("readme.md", "hello".getBytes(StandardCharsets.UTF_8))), CAP))
                    .hasMessageContaining("no .xml entry");
        }
    }

    @Test
    @DisplayName("the form is declared by the media type, in words the caller can correct")
    void mediaTypes() {
        assertThat(TestReportFormat.ofMediaType("application/xml; charset=UTF-8")).isEqualTo(TestReportFormat.JUNIT_XML);
        assertThat(TestReportFormat.ofMediaType("text/xml")).isEqualTo(TestReportFormat.JUNIT_XML);
        assertThat(TestReportFormat.ofMediaType("application/zip")).isEqualTo(TestReportFormat.JUNIT_ZIP);
        assertThatThrownBy(() -> TestReportFormat.ofMediaType("application/json"))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("\"application/json\" is neither");
    }
}
