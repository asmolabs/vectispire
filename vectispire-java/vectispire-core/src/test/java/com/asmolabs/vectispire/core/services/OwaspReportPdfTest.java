package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The OWASP report as a PDF, read back with the library that wrote it.
 *
 * <p>"The endpoint returned bytes" and "somebody can open it and find the report in it" are
 * different claims, and only the second is the feature.
 */
@DisplayName("the OWASP report PDF")
class OwaspReportPdfTest {

    private static final OwaspReportPdf.Subject SUBJECT = new OwaspReportPdf.Subject(
            "Arm Libs Spring",
            "master",
            "1.17.6",
            "gemma4:26b",
            32L,
            Instant.parse("2026-08-21T05:03:00Z"),
            Instant.parse("2026-08-21T07:30:00Z"),
            38);

    @Test
    @DisplayName("carries its provenance on the first page, where a forwarded file is read")
    void theProvenanceIsInTheDocument() throws Exception {
        String text = textOf(OwaspReportPdf.render(SUBJECT, "## A03 — Injection\nA finding."));

        assertThat(text).contains("OWASP Top 10");
        assertThat(text).contains("Arm Libs Spring");
        assertThat(text).contains("version 1.17.6");
        // Which model, from which scan: a reader who cannot see these has no way to judge the
        // report's age or its author, and the file outlives the screen that showed them.
        assertThat(text).contains("gemma4:26b");
        assertThat(text).contains("scan #32");
        assertThat(text).contains("A language model grouped those findings");
    }

    @Test
    @DisplayName("renders the Markdown rather than printing its punctuation")
    void markdownBecomesTypography() throws Exception {
        String text = textOf(OwaspReportPdf.render(
                SUBJECT,
                """
                ## A06 — Vulnerable and Outdated Components

                The **openssl** dependency is behind.

                - Bump to 3.0.14
                - Rebuild the base image

                1. Triage the backlog
                """));

        assertThat(text).contains("A06 — Vulnerable and Outdated Components");
        assertThat(text.replaceAll("\\s+", " ")).contains("The openssl dependency is behind.");
        assertThat(text).contains("Bump to 3.0.14");
        // The asterisks and hashes are typography here, not content. Left in, they read as noise
        // and the reader learns to ignore the emphasis they were meant to carry.
        assertThat(text).doesNotContain("**");
        assertThat(text).doesNotContain("## ");
    }

    @Test
    @DisplayName("wraps a long paragraph instead of writing it off the edge")
    void longProseIsWrapped() throws Exception {
        // The capability the cursor was missing. An overflowing line is invisible in the output:
        // the page looks complete and the sentence is cut where the paper ends.
        String sentence = "This paragraph is deliberately far longer than the printable width of an A4 page "
                + "so that a renderer without word wrapping would push its tail past the right margin "
                + "and lose it entirely, which is exactly the failure this asserts against.";

        // Compared with the line breaks removed: wrapping is exactly what puts them there, so
        // asserting on the raw text would assert on where the breaks fell rather than on the
        // sentence surviving — and that moves with the font.
        String text = flat(OwaspReportPdf.render(SUBJECT, sentence));

        assertThat(text).contains(sentence);
    }

    @Test
    @DisplayName("paginates a long report and numbers what it produced")
    void aLongReportPaginates() throws Exception {
        StringBuilder markdown = new StringBuilder();
        for (int index = 0; index < 120; index++) {
            markdown.append("## A0").append((index % 9) + 1).append(" — Category\n")
                    .append("Finding number ").append(index).append(" with a sentence about it.\n\n");
        }

        byte[] pdf = OwaspReportPdf.render(SUBJECT, markdown.toString());
        try (PDDocument document = Loader.loadPDF(pdf)) {
            assertThat(document.getNumberOfPages()).isGreaterThan(3);
            String text = new PDFTextStripper().getText(document);
            // The tail is present, which is what a silent overflow would have eaten.
            assertThat(text).contains("Finding number 119");
            // "N / total" is a fact only the finished document holds, hence the final pass.
            assertThat(text).contains("/ " + document.getNumberOfPages());
        }
    }

    @Test
    @DisplayName("an empty answer is a sentence, not a blank page")
    void anEmptyReportSaysSo() throws Exception {
        assertThat(textOf(OwaspReportPdf.render(SUBJECT, ""))).contains("The model returned an empty report.");
    }

    /** The extracted text with its line breaks collapsed, for asserting on wrapped prose. */
    private static String flat(byte[] pdf) throws Exception {
        return textOf(pdf).replaceAll("\\s+", " ");
    }

    private static String textOf(byte[] pdf) throws Exception {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            return new PDFTextStripper().getText(document);
        }
    }
}
