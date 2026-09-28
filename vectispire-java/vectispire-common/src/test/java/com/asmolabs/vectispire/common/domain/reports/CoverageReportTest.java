package com.asmolabs.vectispire.common.domain.reports;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The three coverage readers, on small invented reports written the way each tool writes them —
 * JaCoCo's with its DOCTYPE, coverage.py's Cobertura with a {@code SYSTEM} DTD over HTTP, an lcov
 * tracefile concatenated from two runs — and the guards on what they refuse.
 */
@DisplayName("reading a coverage report")
class CoverageReportTest {

    private static final long CAP = 16L * 1024 * 1024;

    static byte[] sample(String name) {
        try (InputStream in = CoverageReportTest.class.getResourceAsStream("/reports/" + name)) {
            return in.readAllBytes();
        } catch (IOException missing) {
            throw new UncheckedIOException(missing);
        }
    }

    private static CoverageReport read(CoverageFormat format, String document) {
        return CoverageReport.read(format, document.getBytes(StandardCharsets.UTF_8), CAP);
    }

    @Nested
    @DisplayName("JaCoCo")
    class Jacoco {

        @Test
        @DisplayName("reads the report's own LINE and BRANCH totals, past its DOCTYPE, never a package's")
        void totals() {
            CoverageReport report = CoverageReport.read(CoverageFormat.JACOCO, sample("jacoco.xml"), CAP);

            assertThat(report.lines()).isEqualTo(new CoverageReport.Counts(7, 12));
            assertThat(report.branches()).contains(new CoverageReport.Counts(3, 4));
            assertThat(report.toolVersion()).isEmpty();
        }

        @Test
        @DisplayName("a report that counted no branch has no branch figure, not 0 of 0")
        void noBranches() {
            CoverageReport report = read(CoverageFormat.JACOCO,
                    "<report name=\"r\"><counter type=\"LINE\" missed=\"1\" covered=\"1\"/></report>");

            assertThat(report.branches()).isEmpty();
            assertThat(read(CoverageFormat.JACOCO, "<report name=\"r\"><counter type=\"LINE\" missed=\"1\" covered=\"1\"/>"
                            + "<counter type=\"BRANCH\" missed=\"0\" covered=\"0\"/></report>").branches())
                    .isEmpty();
        }

        @Test
        @DisplayName("a report with no line is refused: it measured nothing")
        void empty() {
            assertThatThrownBy(() -> read(CoverageFormat.JACOCO,
                            "<!DOCTYPE report PUBLIC \"-//JACOCO//DTD Report 1.1//EN\" \"report.dtd\"><report name=\"r\"/>"))
                    .isInstanceOf(InvalidReportException.class)
                    .hasMessageContaining("counts no line");
            assertThatThrownBy(() -> read(CoverageFormat.JACOCO,
                            "<report name=\"r\"><counter type=\"LINE\" missed=\"0\" covered=\"0\"/></report>"))
                    .hasMessageContaining("counts no line");
        }

        @Test
        @DisplayName("another format declared as JaCoCo, a count that is not one, or a total given twice is refused")
        void refused() {
            assertThatThrownBy(() -> CoverageReport.read(CoverageFormat.JACOCO, sample("cobertura.xml"), CAP))
                    .hasMessageContaining("not <report>");
            assertThatThrownBy(() -> read(CoverageFormat.JACOCO,
                            "<report><counter type=\"LINE\" missed=\"-1\" covered=\"3\"/></report>"))
                    .hasMessageContaining("where a count is expected");
            assertThatThrownBy(() -> read(CoverageFormat.JACOCO, "<report><counter type=\"LINE\" missed=\"1\" covered=\"1\"/>"
                            + "<counter type=\"LINE\" missed=\"0\" covered=\"9\"/></report>"))
                    .hasMessageContaining("twice");
            assertThatThrownBy(() -> read(CoverageFormat.JACOCO, "<report><counter"))
                    .hasMessageContaining("not well-formed XML");
        }
    }

    @Nested
    @DisplayName("Cobertura")
    class Cobertura {

        @Test
        @DisplayName("reads the totals and the producer's version on <coverage>")
        void totals() {
            CoverageReport report = CoverageReport.read(CoverageFormat.COBERTURA, sample("cobertura.xml"), CAP);

            assertThat(report.lines()).isEqualTo(new CoverageReport.Counts(30, 40));
            assertThat(report.branches()).contains(new CoverageReport.Counts(6, 10));
            assertThat(report.toolVersion()).contains("7.6.1");
        }

        @Test
        @DisplayName("a report with only a rate is refused rather than recomputed, and so is lines-valid=0")
        void refused() {
            assertThatThrownBy(() -> read(CoverageFormat.COBERTURA, "<coverage line-rate=\"0.8\"/>"))
                    .hasMessageContaining("does not state lines-covered and lines-valid");
            assertThatThrownBy(() -> read(CoverageFormat.COBERTURA,
                            "<coverage lines-covered=\"0\" lines-valid=\"0\"/>"))
                    .hasMessageContaining("counts no line");
            assertThatThrownBy(() -> read(CoverageFormat.COBERTURA,
                            "<coverage lines-covered=\"9\" lines-valid=\"4\"/>"))
                    .hasMessageContaining("never more than its total");
            assertThatThrownBy(() -> CoverageReport.read(CoverageFormat.COBERTURA, sample("jacoco.xml"), CAP))
                    .hasMessageContaining("not <coverage>");
        }

        @Test
        @DisplayName("branches-valid=0 is no branch figure")
        void noBranches() {
            assertThat(read(CoverageFormat.COBERTURA, "<coverage lines-covered=\"1\" lines-valid=\"2\" "
                            + "branches-covered=\"0\" branches-valid=\"0\"/>").branches())
                    .isEmpty();
        }
    }

    @Nested
    @DisplayName("lcov")
    class Lcov {

        @Test
        @DisplayName("merges a file listed by two runs: a line hit by either is covered, and counted once")
        void merges() {
            CoverageReport report = CoverageReport.read(CoverageFormat.LCOV, sample("lcov.info"), CAP);

            // cart.ts: 3, 4 hit; 7 hit by the second run; 8 by neither. price.ts: 1 of 2.
            assertThat(report.lines()).isEqualTo(new CoverageReport.Counts(4, 6));
            // (4,0,0) taken; (4,0,1) taken by the first run, not by the second ("-"): taken.
            assertThat(report.branches()).contains(new CoverageReport.Counts(2, 2));
        }

        @Test
        @DisplayName("a tracefile with no DA line, cut before end_of_record, or not lcov at all is refused")
        void refused() {
            assertThatThrownBy(() -> read(CoverageFormat.LCOV, "TN:\nSF:a.c\nend_of_record\n"))
                    .hasMessageContaining("counts no line");
            assertThatThrownBy(() -> read(CoverageFormat.LCOV, "SF:a.c\nDA:1,1\n"))
                    .hasMessageContaining("cut short");
            assertThatThrownBy(() -> read(CoverageFormat.LCOV, "{\"total\": {\"lines\": {\"pct\": 100}}}"))
                    .hasMessageContaining("not an lcov record");
            assertThatThrownBy(() -> read(CoverageFormat.LCOV, "DA:1,1\n"))
                    .hasMessageContaining("outside an SF record");
            assertThatThrownBy(() -> read(CoverageFormat.LCOV, "TN:x\n"))
                    .hasMessageContaining("no SF record");
            assertThatThrownBy(() -> CoverageReport.read(CoverageFormat.LCOV, new byte[] {(byte) 0xc3, 0x28}, CAP))
                    .hasMessageContaining("not UTF-8");
        }

        @Test
        @DisplayName("a line number past the bound is refused, never allocated for")
        void boundedLineNumbers() {
            assertThatThrownBy(() -> read(CoverageFormat.LCOV, "SF:a.c\nDA:2147483647,1\nend_of_record\n"))
                    .hasMessageContaining("outside 1 to");
            assertThatThrownBy(() -> read(CoverageFormat.LCOV, "SF:a.c\nDA:1,99999999999999999999\nend_of_record\n"))
                    .isInstanceOf(InvalidReportException.class)
                    .hasMessageContaining("where a number is expected");
        }
    }

    @Nested
    @DisplayName("the XML guards")
    class Guards {

        @Test
        @DisplayName("an external entity is refused, and the file it names is never read")
        void externalEntity(@TempDir Path directory) throws IOException {
            Path secret = Files.writeString(directory.resolve("secret.txt"), "the database password");
            String document = "<?xml version=\"1.0\"?><!DOCTYPE report [<!ENTITY xxe SYSTEM \"" + secret.toUri()
                    + "\">]><report name=\"&xxe;\"><counter type=\"LINE\" missed=\"0\" covered=\"1\"/></report>";

            assertThatThrownBy(() -> read(CoverageFormat.JACOCO, document))
                    .isInstanceOf(InvalidReportException.class)
                    .hasMessageContaining("internal DTD subset")
                    .message().doesNotContain("password");
        }

        @Test
        @DisplayName("an expansion bomb is refused before anything expands")
        void billionLaughs() {
            StringBuilder entities = new StringBuilder("<!ENTITY l0 \"lol\">");
            for (int i = 1; i < 10; i++) {
                entities.append("<!ENTITY l").append(i).append(" \"");
                entities.append(("&l" + (i - 1) + ";").repeat(10)).append("\">");
            }
            String document = "<?xml version=\"1.0\"?><!DOCTYPE report [" + entities + "]><report name=\"&l9;\"/>";

            assertThatThrownBy(() -> read(CoverageFormat.JACOCO, document)).hasMessageContaining("internal DTD subset");
        }

        @Test
        @DisplayName("a DTD named over HTTP is tolerated and never fetched")
        void dtdNeverLoaded() throws IOException {
            AtomicInteger requests = new AtomicInteger();
            HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.createContext("/", exchange -> {
                requests.incrementAndGet();
                byte[] dtd = "<!ENTITY injected \"from the network\">".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, dtd.length);
                exchange.getResponseBody().write(dtd);
                exchange.close();
            });
            server.start();
            try {
                String dtd = "http://127.0.0.1:" + server.getAddress().getPort() + "/coverage-04.dtd";
                CoverageReport report = read(CoverageFormat.COBERTURA, "<?xml version=\"1.0\"?><!DOCTYPE coverage SYSTEM \""
                        + dtd + "\"><coverage lines-covered=\"1\" lines-valid=\"2\"/>");

                assertThat(report.lines()).isEqualTo(new CoverageReport.Counts(1, 2));
                // What the DTD would have declared is not defined: in text the reference is refused, in
                // an attribute the parser leaves nothing — here, no version.
                assertThatThrownBy(() -> read(CoverageFormat.COBERTURA, "<?xml version=\"1.0\"?><!DOCTYPE coverage SYSTEM \""
                                + dtd + "\"><coverage lines-covered=\"1\" lines-valid=\"2\">&injected;</coverage>"))
                        .isInstanceOf(InvalidReportException.class)
                        .hasMessageContaining("entities are not expanded");
                assertThat(read(CoverageFormat.COBERTURA, "<?xml version=\"1.0\"?><!DOCTYPE coverage SYSTEM \"" + dtd
                                + "\"><coverage lines-covered=\"1\" lines-valid=\"2\" version=\"&injected;\"/>").toolVersion())
                        .isEmpty();
                assertThatThrownBy(() -> read(CoverageFormat.COBERTURA, "<?xml version=\"1.0\"?><!DOCTYPE coverage SYSTEM \""
                                + dtd + "\"><coverage lines-covered=\"&injected;\" lines-valid=\"2\"/>"))
                        .hasMessageContaining("where a count is expected");
                assertThat(requests).hasValue(0);
            } finally {
                server.stop(0);
            }
        }

        @Test
        @DisplayName("nesting past the bound is refused")
        void depth() {
            String document = "<report>" + "<group>".repeat(SafeXml.MAX_DEPTH) + "</group>".repeat(SafeXml.MAX_DEPTH)
                    + "</report>";

            assertThatThrownBy(() -> read(CoverageFormat.JACOCO, document)).hasMessageContaining("deeper than");
        }

        @Test
        @DisplayName("a document past the ceiling is refused unread")
        void ceiling() {
            assertThatThrownBy(() -> CoverageReport.read(CoverageFormat.JACOCO, new byte[11], 10))
                    .hasMessageContaining("larger than the 10 bytes");
            assertThatThrownBy(() -> CoverageReport.read(CoverageFormat.JACOCO, new byte[0], 10))
                    .hasMessageContaining("empty");
        }
    }

    @Test
    @DisplayName("the format is declared in words the caller can correct")
    void formats() {
        assertThat(CoverageFormat.parse(" JaCoCo ")).isEqualTo(CoverageFormat.JACOCO);
        assertThatThrownBy(() -> CoverageFormat.parse("clover"))
                .isInstanceOf(InvalidInputException.class)
                .hasMessage("Declare the report's format as one of jacoco, cobertura, lcov; \"clover\" is not one of them.");
        assertThatThrownBy(() -> CoverageFormat.parse(null)).hasMessageContaining("jacoco, cobertura, lcov.");
    }
}
