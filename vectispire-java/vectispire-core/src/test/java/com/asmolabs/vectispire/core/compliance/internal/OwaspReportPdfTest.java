package com.asmolabs.vectispire.core.compliance.internal;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.aireview.AdviceLanguage;
import com.asmolabs.vectispire.common.domain.gate.Observation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
        String text = textOf(english(SUBJECT, "## A03 — Injection\nA finding."));

        assertThat(text).contains("OWASP Top 10:2021");
        assertThat(text).contains("Arm Libs Spring");
        assertThat(text).contains("version 1.17.6");
        // Which model, from which scan: a reader who cannot see these has no way to judge the
        // report's age or its author, and the file outlives the screen that showed them.
        assertThat(text).contains("gemma4:26b");
        assertThat(text).contains("scan #32");
        assertThat(text).contains("A language model grouped those findings");
        // The sentence the OWASP grid contradicts — a category can be examined and come back clean.
        assertThat(text.replaceAll("\\s+", " ")).doesNotContain("means no scanner here looked for it");
        assertThat(text.replaceAll("\\s+", " ")).contains("found nothing open");
    }

    @Test
    @DisplayName("says the categories are the grid's only for a report that was handed them")
    void thePlacementIsStatedAsRecorded() throws Exception {
        OwaspReportPdf.Subject placed = new OwaspReportPdf.Subject(
                SUBJECT.targetName(), SUBJECT.branch(), SUBJECT.projectVersion(), SUBJECT.model(), SUBJECT.scanId(),
                SUBJECT.scanAt(), SUBJECT.generatedAt(), SUBJECT.openIssues(), SUBJECT.brandName(), true);

        String now = textOf(english(placed, "## A07 — Identification and Authentication Failures"))
                .replaceAll("\\s+", " ");
        String before = textOf(english(SUBJECT, "## A02 — Cryptographic Failures"))
                .replaceAll("\\s+", " ");

        assertThat(now).contains("Vectispire's own rules place it in");
        assertThat(now).doesNotContain("grouped those findings under the OWASP categories");
        // A report the model placed itself must not be presented as placed by rule.
        assertThat(before).doesNotContain("Vectispire's own rules place it in");
    }

    @Test
    @DisplayName("renders the Markdown rather than printing its punctuation")
    void markdownBecomesTypography() throws Exception {
        String text = textOf(english(
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
        String text = flat(english(SUBJECT, sentence));

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

        byte[] pdf = english(SUBJECT, markdown.toString());
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
        assertThat(textOf(english(SUBJECT, ""))).contains("The model returned an empty report.");
    }

    /**
     * A grid whose lines say different things: a secret open (A07), the misconfiguration step absent on one
     * repository and the other never scanned (A05), code analysis reaching one repository of two (A03), and
     * the categories nothing here covers.
     */
    private static final OwaspCoverage.Grid GRID = OwaspCoverage.assess(new OwaspCoverage.Measurement(
            true,
            true,
            Map.of(FindingType.SECRET, 2L, FindingType.VULNERABILITY, 0L, FindingType.EOL, 0L, FindingType.IAC, 0L),
            Set.of("A03"),
            Map.of(),
            List.of(
                    new OwaspCoverage.Evidence(
                            new ScanTarget.Repository(1),
                            Observation.OK,
                            Optional.of(EnumSet.of(FindingType.VULNERABILITY, FindingType.EOL, FindingType.LICENSE,
                                    FindingType.SECRET, FindingType.SAST)),
                            Optional.of(Set.of(Language.JAVA)),
                            Optional.of(Set.of("A03"))),
                    OwaspCoverage.Evidence.neverScanned(new ScanTarget.Repository(2)))));

    @Test
    @DisplayName("asked in French, writes its own words in French — the grid's reasons included — and the model's as written")
    void frenchLabelsAndTheModelAsWritten() throws Exception {
        String text = flat(OwaspReportPdf.render(SUBJECT, "## A07 — Identification and Authentication Failures\n"
                + "Two secrets are exposed.", GRID, AdviceLanguage.FRENCH));

        assertThat(text).contains(
                "OWASP Top 10:2021 — rapport de posture",
                "Constats ouverts au moment de la rédaction : 38",
                "Établi à partir du scan #32 du 2026-08-21 05:03 UTC",
                "Rédigé par gemma4:26b",
                "Comment le lire",
                "Couverture de l'OWASP Top 10:2021, par règle",
                "Aucun scanner de ce déploiement ne produit de constat dans cette catégorie.",
                "Constats (2) — Des constats ouverts sont placés ici par règle.",
                "1 des dépôts concernés par cette catégorie (2 au total) n'a pas été examiné pour elle par l'analyse "
                        + "de code (1 n'a jamais terminé de scan)",
                "2 des cibles concernées par cette catégorie (2 au total) n'ont pas été examinées pour elle par "
                        + "configuration d'infrastructure (1 n'a jamais terminé de scan, 1 dont le dernier scan n'a pas "
                        + "terminé cette étape)",
                "rapport OWASP Top 10:2021 — Arm Libs Spring");
        // The model's text is its own: printed as written, and the page says so rather than translating it.
        assertThat(text).contains("Two secrets are exposed.", "reproduit tel qu'il l'a écrit");
        assertThat(text).doesNotContain("How to read this", "Open findings at the time of writing",
                "No scanner in this deployment", "posture report");
    }

    @Test
    @DisplayName("carries the grid's ten categories, each with its state and why, as the rules read them")
    void theGridsTenRows() throws Exception {
        for (AdviceLanguage language : AdviceLanguage.values()) {
            String text = flat(OwaspReportPdf.render(SUBJECT, "## A03 — Injection\nA finding.", GRID, language));
            for (OwaspCoverage.CoverageLine line : GRID.lines()) {
                assertThat(text).as("%s in %s", line.id(), language)
                        .contains(line.id() + " " + line.title() + " " + OwaspReportWords.state(line, language) + " — ");
            }
        }
        assertThat(GRID.lines()).hasSize(10);
    }

    @Test
    @DisplayName("in English by default: the route's own sentences, and no word about translation")
    void englishIsUnchanged() throws Exception {
        String text = flat(english(SUBJECT, "## A03 — Injection\nA finding."));

        assertThat(text).contains("OWASP Top 10:2021 — posture report", "How to read this",
                "OWASP Top 10:2021 coverage, by rule", "No scanner here — No scanner in this deployment produces a "
                        + "finding in this category.");
        for (OwaspCoverage.CoverageLine line : GRID.lines()) {
            assertThat(text).as(line.id()).contains(line.because());
        }
        assertThat(text).doesNotContain("Comment le lire", "reproduit tel qu'il l'a écrit", "translated");
    }

    /** The document as a caller naming no language gets it. */
    private static byte[] english(OwaspReportPdf.Subject subject, String markdown) {
        return OwaspReportPdf.render(subject, markdown, GRID, AdviceLanguage.ENGLISH);
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
