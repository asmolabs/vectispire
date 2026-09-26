package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.compliance.ComplianceControl;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.core.services.compliance.ComplianceReportPdf;
import com.asmolabs.vectispire.core.services.issues.TriageHistory;
import com.asmolabs.vectispire.core.services.issues.TriageHistory.Decision;
import com.asmolabs.vectispire.core.services.issues.TriageHistory.ObservedIssue;
import com.asmolabs.vectispire.core.services.issues.TriageHistory.Repository;
import com.asmolabs.vectispire.core.services.issues.TriageHistory.Scan;
import com.asmolabs.vectispire.core.services.issues.TriageHistoryReport;
import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Two documents handed to auditors, read back as text.
 *
 * <p>Both were covered only by a route test asserting that a PDF came back. A report can be a valid
 * PDF and still have lost its tail off the page, printed "null days" or dropped the sentence that
 * says why a figure is zero — none of which a content type shows.
 */
@DisplayName("the PDF reports, read back")
class ReportsReadBackTest {

    private static final Instant AT = Instant.parse("2026-09-24T08:00:00Z");

    @Nested
    @DisplayName("the compliance report")
    class Compliance {

        @Test
        @DisplayName("every control of every framework is in the document, across pages")
        void everyControlIsPrinted() throws Exception {
            List<ComplianceEvaluation.ControlAssessment> assessments = IntStream.rangeClosed(1, 30)
                    .mapToObj(i -> new ComplianceEvaluation.ControlAssessment(
                            new ComplianceControl("CTRL-" + i, "Control " + i, "The requirement of control " + i + ", written at length so that it wraps.",
                                    ComplianceControl.Category.VULNERABILITY_MANAGEMENT),
                            ComplianceControl.Status.PARTIAL, 50, "state-" + i, "fix-" + i))
                    .toList();
            ComplianceEvaluation nis2 = new ComplianceEvaluation(ComplianceFramework.NIS_2, 50, ComplianceControl.Status.PARTIAL, assessments);

            String text = readBack(ComplianceReportPdf.render(
                    new ComplianceReportPdf.Subject(AT, 4, 3, 12.5, 2), List.of(nis2)));

            assertThat(IntStream.rangeClosed(1, 30).mapToObj(i -> "CTRL-" + i + ":"))
                    .allSatisfy(id -> assertThat(text).contains(id));
            assertThat(text).contains("state-30").contains("fix-30");
        }

        @Test
        @DisplayName("an unmeasured remediation time reads N/A, not \"null days\", and a blank brand falls back")
        void absentFiguresAreSaid() throws Exception {
            String text = readBack(ComplianceReportPdf.render(
                    new ComplianceReportPdf.Subject(AT, 0, 0, null, 0, "  "), List.of()));

            assertThat(text).contains("Mean Time to Remediate (MTTR): N/A").doesNotContain("null");
            assertThat(text).contains("Vectispire — Regulatory Compliance");
        }
    }

    @Nested
    @DisplayName("the triage history report")
    class History {

        @Test
        @DisplayName("names the decision, who took it and the scan's reported failure")
        void decisionsAndFailuresArePrinted() throws Exception {
            Decision decision = new Decision("under_review", "not_affected", "vulnerable_code_not_present",
                    "not compiled in", "alice", "manual", AT, null, 3L, "1.4.2");
            ObservedIssue issue = new ObservedIssue(9L, "vulnerability", "CVE-2026-1234", "HIGH", "openssl", "3.0.1",
                    null, "open", "not_affected", AT, null, List.of(decision));
            Scan scan = new Scan(3L, "completed", "main", "1.4.2", "maven", AT, 1000L, 1, 1, 0,
                    "sast: semgrep timed out", List.of(issue));

            String text = readBack(TriageHistoryReport.render(
                    new Repository(1L, "shop", "https://***@example.invalid/shop.git", "main", "1.4.2", "maven", 1, AT, 1, 1),
                    List.of(scan), AT));

            assertThat(text).contains("CVE-2026-1234").contains("alice").contains("semgrep timed out");
            // The URL arrives masked from the history service and is printed as it arrives.
            assertThat(text).contains("https://***@example.invalid/shop.git");
        }

        @Test
        @DisplayName("a target with no decision says why the count is zero")
        void zeroDecisionsIsExplained() throws Exception {
            String text = readBack(TriageHistoryReport.render(
                    new Repository(1L, "shop", "https://example.invalid/shop.git", "main", null, null, 0, AT, 0, 0),
                    List.of(), AT));

            assertThat(text).contains("No triage decision has been recorded for this target.");
            assertThat(text).contains("Current version: unknown");
        }
    }

    private static String readBack(byte[] pdf) throws Exception {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            return new PDFTextStripper().getText(document);
        }
    }
}
