package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.compliance.ComplianceControl;
import com.asmolabs.zanshin.common.domain.compliance.ComplianceEvaluation;
import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * Renders an executive compliance report for auditors and CISOs.
 */
public final class ComplianceReportPdf {

    private ComplianceReportPdf() {}

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private static final Color INK = new Color(0x1F, 0x2A, 0x37);
    private static final Color ACCENT = new Color(0x1E, 0x40, 0xAF); // Deep blue
    private static final Color SUCCESS = new Color(0x16, 0xA3, 0x4A); // Green
    private static final Color WARNING = new Color(0xEA, 0x58, 0x0C); // Orange
    private static final Color DANGER = new Color(0xDC, 0x26, 0x26); // Red
    private static final Color MUTED = new Color(0x6B, 0x72, 0x80);
    private static final Color BAND = new Color(0xF3, 0xF4, 0xF6);

    public record Subject(
            Instant generatedAt,
            int totalTargets,
            int passingTargets,
            Double overallMttrDays,
            long overdueCount) {}

    public static byte[] render(Subject subject, List<ComplianceEvaluation> evaluations) {
        try (PDDocument document = new PDDocument();
                ByteArrayOutputStream bytes = new ByteArrayOutputStream()) {

            ReportCursor cursor = new ReportCursor(document);
            cover(cursor, subject, evaluations);
            body(cursor, evaluations);
            cursor.close("Zanshin — Executive Regulatory Compliance Report");

            document.save(bytes);
            return bytes.toByteArray();
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not render the Compliance PDF report", failed);
        }
    }

    private static void cover(ReportCursor cursor, Subject subject, List<ComplianceEvaluation> evaluations) {
        cursor.text("Zanshin — Regulatory Compliance & Posture Audit", ReportCursor.HELVETICA_BOLD_16, INK);
        cursor.rule(ACCENT);
        cursor.gap();

        cursor.band(ReportCursor.LINE * 4.4f, BAND);
        cursor.text("Generated: " + STAMP.format(subject.generatedAt()), ReportCursor.HELVETICA_10, INK);
        cursor.text("Monitored Targets: " + subject.totalTargets() + "  (" + subject.passingTargets() + " passing active Gates)", ReportCursor.HELVETICA_10, INK);
        cursor.text("Mean Time to Remediate (MTTR): " + (subject.overallMttrDays() != null ? subject.overallMttrDays() + " days" : "N/A"), ReportCursor.HELVETICA_10, INK);
        cursor.text("Vulnerabilities in SLA Breach: " + subject.overdueCount(), ReportCursor.HELVETICA_10, subject.overdueCount() > 0 ? DANGER : SUCCESS);
        cursor.gap();

        cursor.text("Executive Summary by Framework", ReportCursor.HELVETICA_BOLD_12, INK);
        for (ComplianceEvaluation eval : evaluations) {
            Color statusColor = eval.overallStatus() == ComplianceControl.Status.COMPLIANT ? SUCCESS
                    : eval.overallStatus() == ComplianceControl.Status.PARTIAL ? WARNING : DANGER;
            cursor.text(
                    eval.framework().getTitle() + " — " + eval.scorePercentage() + "% (" + eval.overallStatus() + ")",
                    ReportCursor.HELVETICA_BOLD_10,
                    statusColor);
            cursor.text("  " + eval.framework().getDescription(), ReportCursor.HELVETICA_9, MUTED);
        }
        cursor.gap();
        cursor.rule(MUTED);
        cursor.gap();
    }

    private static void body(ReportCursor cursor, List<ComplianceEvaluation> evaluations) {
        for (ComplianceEvaluation eval : evaluations) {
            cursor.text(eval.framework().getTitle(), ReportCursor.HELVETICA_BOLD_12, ACCENT);
            cursor.text(eval.framework().getDescription(), ReportCursor.HELVETICA_9, MUTED);
            cursor.gap();

            for (ComplianceEvaluation.ControlAssessment assessment : eval.controls()) {
                Color controlColor = assessment.status() == ComplianceControl.Status.COMPLIANT ? SUCCESS
                        : assessment.status() == ComplianceControl.Status.PARTIAL ? WARNING : DANGER;

                cursor.text(
                        "[" + assessment.status() + " — " + assessment.scorePercentage() + "%] "
                                + assessment.control().id() + ": " + assessment.control().name(),
                        ReportCursor.HELVETICA_BOLD_10,
                        controlColor);

                cursor.paragraph("Requirement: " + assessment.control().requirement(), ReportCursor.HELVETICA_9, 10);
                cursor.paragraph("Current State: " + assessment.details(), ReportCursor.HELVETICA_9, 10);
                cursor.paragraph("Remediation: " + assessment.remediationGuidance(), ReportCursor.HELVETICA_9, 10);
                cursor.gap();
            }
            cursor.rule(BAND);
            cursor.gap();
        }
    }
}
