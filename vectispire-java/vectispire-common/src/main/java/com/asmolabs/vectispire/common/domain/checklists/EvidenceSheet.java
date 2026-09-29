package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The sheet the renderer adds to the organisation's workbook (decision 0032 §10, question 12): what each
 * answer rests on, and who stands behind the revision. The template's own sheets hold only the
 * organisation's columns; everything Vectispire adds is here, where nobody mistakes it for the template.
 *
 * <p>In English, whatever the template's language: its labels are the product's, like the rest of what it
 * writes, while the answers in the checklist sheet are the organisation's own words. Every instant is
 * written in UTC, ISO 8601, as text — a date cell would be read in the reader's own zone.
 */
final class EvidenceSheet {

    static final List<String> COLUMNS = List.of("Line", "Control", "Answer", "Answered by", "Answered at", "Measurement",
            "As of", "Answer and measurement", "Measurement evidence", "Proofs");

    private static final int[] WIDTHS = {6, 48, 14, 20, 22, 22, 22, 24, 60, 70};

    private EvidenceSheet() {}

    static String xml(ChecklistStatement statement, ChecklistLayout layout, String namespace) {
        List<List<Object>> rows = new ArrayList<>();
        rows.add(List.of(banner(statement)));
        rows.add(List.of());
        rows.add(List.copyOf(COLUMNS));
        for (ChecklistStatement.Line line : statement.lines()) {
            Optional<ChecklistStatement.Answer> answer = Optional.ofNullable(line.answer());
            Optional<ChecklistStatement.Measured> measured = Optional.ofNullable(line.measurement());
            rows.add(List.of(
                    line.position(),
                    line.control(),
                    answer.map(given -> ChecklistRenderer.word(layout.answers(), given)).orElse("unanswered"),
                    answer.map(EvidenceSheet::answeredBy).orElse(""),
                    answer.map(given -> instant(given.answeredAt())).orElse(""),
                    measured.map(EvidenceSheet::outcome).orElse("not measured here"),
                    measured.map(ChecklistStatement.Measured::asOf).map(EvidenceSheet::instant).orElse(""),
                    reconciliation(line.reconciliation()),
                    measured.map(EvidenceSheet::evidence).orElse(""),
                    proofs(line.evidence())));
        }
        rows.add(List.of());
        rows.add(List.of("Project", statement.project().name() + " (" + statement.project().id() + ")"));
        rows.add(List.of("Revision", statement.revision()));
        ChecklistStatement.Template template = statement.template();
        rows.add(List.of("Template", template.slug() + " — " + template.name() + ", version " + template.version()
                + (template.label() == null || template.label().isBlank() ? "" : " (" + template.label() + ")")));
        rows.add(List.of("Template source SHA-256", template.sourceSha256()));
        rows.add(List.of("Opened by", act(statement.opened())));
        rows.add(List.of("Submitted by", Optional.ofNullable(statement.submitted()).map(EvidenceSheet::act).orElse("not submitted")));
        rows.add(List.of("Signed off by", Optional.ofNullable(statement.signedOff()).map(EvidenceSheet::act).orElse("not signed off")));
        rows.add(List.of("Four-eyes rule", fourEyes(statement)));
        rows.add(List.of("Produced by", "Vectispire " + Optional.ofNullable(statement.productVersion())
                .orElse("(version not stated by the build)") + " at " + instant(statement.producedAt())));
        rows.add(List.of("Instants", "UTC, ISO 8601"));

        StringBuilder sheet = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n")
                .append("<worksheet xmlns=\"").append(XmlCursor.escapeAttribute(namespace)).append("\"><cols>");
        for (int i = 0; i < WIDTHS.length; i++) {
            sheet.append("<col min=\"").append(i + 1).append("\" max=\"").append(i + 1).append("\" width=\"").append(WIDTHS[i])
                    .append("\" customWidth=\"1\"/>");
        }
        sheet.append("</cols><sheetData>");
        for (int r = 0; r < rows.size(); r++) {
            List<Object> row = rows.get(r);
            if (row.isEmpty()) {
                continue;
            }
            sheet.append("<row r=\"").append(r + 1).append("\">");
            for (int c = 0; c < row.size(); c++) {
                String reference = new CellRef(c + 1, r + 1).toString();
                Object value = row.get(c);
                if (value instanceof Integer number) {
                    sheet.append("<c r=\"").append(reference).append("\"><v>").append(number).append("</v></c>");
                } else if (!value.toString().isEmpty()) {
                    sheet.append("<c r=\"").append(reference).append("\" t=\"inlineStr\"><is><t xml:space=\"preserve\">")
                            .append(XmlCursor.escapeText(BoundedText.clip(value.toString(), WorkbookReader.MAX_CELL_TEXT)))
                            .append("</t></is></c>");
                }
            }
            sheet.append("</row>");
        }
        return sheet.append("</sheetData></worksheet>").toString();
    }

    /** The first line: whether anybody signed what follows. */
    static String banner(ChecklistStatement statement) {
        if (statement.signed()) {
            return "Signed off by " + statement.signedOff().by() + " at " + instant(statement.signedOff().at())
                    + " — this document was produced and signed with the sign-off.";
        }
        if (statement.signedOff() != null) {
            // Signed off before documents were signed: the revision is, the document is not.
            return "Signed off by " + statement.signedOff().by() + " at " + instant(statement.signedOff().at())
                    + " — but no signed document was produced then: this rendering is not signed.";
        }
        return ChecklistRenderer.DRAFT_BANNER;
    }

    private static String answeredBy(ChecklistStatement.Answer answer) {
        String by = answer.answeredBy();
        if (answer.carriedBy() != null) {
            by += " (carried by " + answer.carriedBy() + ")";
        }
        return answer.needsConfirmation() ? by + " — awaiting confirmation" : by;
    }

    private static String outcome(ChecklistStatement.Measured measured) {
        String outcome = measured.outcome().replace('_', ' ');
        return measured.reason() == null ? outcome : outcome + " (" + measured.reason().replace('_', ' ') + ")";
    }

    private static String evidence(ChecklistStatement.Measured measured) {
        return measured.summary() + " — evidence SHA-256 " + measured.evidenceDigest()
                + (measured.purpose().equals("read") ? "; computed for this rendering" : "");
    }

    /** The reconciliation in the words the screen and the ADR use (§6). */
    static String reconciliation(String wireName) {
        if (wireName == null) {
            return "";
        }
        return switch (wireName) {
            case "declared_not_measured" -> "declared, not measured";
            case "excluded" -> "excluded (not applicable)";
            default -> wireName.replace('_', ' ');
        };
    }

    private static String proofs(List<ChecklistStatement.Proof> proofs) {
        return proofs.stream()
                .filter(proof -> proof.withdrawnAt() == null)
                .map(proof -> ("file".equals(proof.kind())
                                ? "file " + proof.fileName() + " SHA-256 " + proof.sha256()
                                : "link " + proof.link())
                        + ", performed on " + proof.performedOn()
                        + (proof.validUntil() == null ? "" : ", valid until " + proof.validUntil()))
                .collect(Collectors.joining("\n"));
    }

    private static String fourEyes(ChecklistStatement statement) {
        if (statement.fourEyesRequired() == null) {
            return "not signed off: no rule has applied yet";
        }
        return statement.fourEyesRequired()
                ? "required — the signer is none of the revision's authors"
                : "not required — the platform's four-eyes setting was off at the sign-off";
    }

    private static String act(ChecklistStatement.Act act) {
        return act.by() + " at " + instant(act.at());
    }

    private static String instant(Instant instant) {
        return instant == null ? "" : instant.toString();
    }
}
