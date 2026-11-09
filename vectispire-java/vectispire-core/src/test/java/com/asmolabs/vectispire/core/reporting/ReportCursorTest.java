package com.asmolabs.vectispire.core.reporting;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.stream.IntStream;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The pagination every PDF report relies on.
 *
 * <p>Five reports write through this class and none of them tested it: the defect it exists for —
 * the tail of a long document drawn off the page, the file looking complete — is invisible to a
 * test that only checks a PDF was produced. So these read the text back, page by page.
 */
@DisplayName("writing a report down its pages")
class ReportCursorTest {

    @Test
    @DisplayName("a document longer than a page continues on the next one, with every line readable")
    void everyLineLandsOnAPage() throws Exception {
        List<String> lines = IntStream.rangeClosed(1, 182).mapToObj(i -> "finding-" + i).toList();

        byte[] pdf = render(cursor -> {
            for (String line : lines) {
                cursor.text(line, ReportCursor.HELVETICA_10);
            }
        });

        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThat(document.getNumberOfPages()).isGreaterThan(1);
            String text = new PDFTextStripper().getText(document);
            // 182 was the real backlog on which lines past the first page vanished.
            assertThat(lines).allSatisfy(line -> assertThat(text).contains(line));
        }
    }

    @Test
    @DisplayName("a wrapped paragraph keeps every word, and each line fits the width")
    void wrappingLosesNothing() {
        String prose = "The deployment key attached to this repository could not be read, so the clone "
                + "proceeded with no identity and failed as permission denied at the provider.";

        List<String> lines = ReportCursor.wrap(prose, ReportCursor.HELVETICA_10, 120);

        assertThat(lines).hasSizeGreaterThan(1);
        assertThat(String.join(" ", lines)).isEqualTo(prose);
    }

    @Test
    @DisplayName("a single word wider than the column gets a line of its own rather than being dropped")
    void anOverlongWordIsKept() {
        String word = "pkg:maven/org.example.very.long.group/artifact-with-a-long-name@1.2.3";

        assertThat(ReportCursor.wrap("see " + word + " now", ReportCursor.HELVETICA_10, 60)).contains(word);
    }

    @Test
    @DisplayName("text the standard fonts cannot encode costs a glyph, not the report")
    void unencodableTextDoesNotFailTheDocument() {
        // A package name from a registry allowing non-Latin scripts is enough to reach this.
        assertThatCode(() -> render(cursor -> cursor.text("パッケージ lodash 4.17.21", ReportCursor.HELVETICA_10)))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("truncation marks what it cut, and leaves what fits alone")
    void truncationIsMarked() {
        assertThat(ReportCursor.truncate("short", 10)).isEqualTo("short");
        assertThat(ReportCursor.truncate("a-very-long-identifier", 10)).hasSize(10).endsWith("…");
    }

    private interface Drawing {
        void on(ReportCursor cursor) throws Exception;
    }

    private static byte[] render(Drawing drawing) throws Exception {
        try (PDDocument document = new PDDocument(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            ReportCursor cursor = new ReportCursor(document);
            drawing.on(cursor);
            cursor.close();
            document.save(out);
            return out.toByteArray();
        }
    }
}
