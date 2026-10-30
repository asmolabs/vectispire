package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.aireview.AdviceLanguage;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.exports.SpreadsheetCells;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyHistoryService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The OWASP coverage grid as rows, for a spreadsheet or a register kept outside this product.
 *
 * <p><b>One row per category, in the standard's order, and all ten every time.</b> A category nothing
 * here can measure is the row an assessor most needs to see in the file: dropping the grey ones would
 * hand them a sheet that reads as complete coverage. The scope is repeated on every row rather than
 * written once above the header, so a row pasted into another sheet still says what it was computed
 * over — and whether that was the whole project or only the part its reader sees.
 *
 * <p><b>The reason is written out in the requested language</b>, from the same code the screen
 * translates ({@link OwaspReportWords#reason}), and the code is kept in a column of its own: the
 * sentence is for a person, the code for a filter.
 *
 * <p><b>Every cell is neutralized before it is quoted</b> ({@link SpreadsheetCells}): a project's or a
 * solution's name is chosen by whoever may create one, and a declaration's justification, owner and
 * evidence are free text written by a security lead. Quoting alone protects nothing — the spreadsheet
 * strips the quotes and then evaluates.
 */
public final class OwaspGridCsv {

    private OwaspGridCsv() {}

    /** Every row, the last included, as spreadsheets and RFC 4180 expect, and as the issue export does. */
    private static final String ROW_TERMINATOR = "\r\n";

    private static final List<String> HEADER = List.of(
            "category",
            "title",
            "state",
            "findings",
            "reason_code",
            "reason",
            "declaration_applicability",
            "declaration_justification",
            "declaration_implementation",
            "declaration_evidence_source",
            "declaration_external_evidence",
            "declaration_owner",
            "declaration_decided_by",
            "declaration_decided_at",
            "declaration_review_due_at",
            "scope_kind",
            "scope_id",
            "scope_name",
            "scope_partial");

    /**
     * @param lines the grid in the standard's order
     * @param declarations what the organisation states, by category; a category without one leaves its
     *     columns empty — "nothing declared", never a default
     * @param scope the project or solution the grid covers, null for the reader's estate — whose kind
     *     reads {@code estate} and whose id and name stay empty
     */
    public static String render(
            List<OwaspCoverage.CoverageLine> lines,
            Map<String, Declaration> declarations,
            OwaspWeeklyHistoryService.OwaspWeeklyScope scope,
            AdviceLanguage language) {
        StringBuilder csv = new StringBuilder();
        csv.append(String.join(",", HEADER)).append(ROW_TERMINATOR);
        for (OwaspCoverage.CoverageLine line : lines) {
            Declaration declaration = declarations.get(line.id());
            csv.append(Stream.of(
                                    line.id(),
                                    line.title(),
                                    line.state().name(),
                                    String.valueOf(line.findings()),
                                    line.reason().code().name(),
                                    OwaspReportWords.reason(line, language),
                                    declaration == null ? null : nameOf(declaration.applicability()),
                                    declaration == null ? null : declaration.justification(),
                                    declaration == null ? null : nameOf(declaration.implementation()),
                                    declaration == null ? null : nameOf(declaration.evidenceSource()),
                                    declaration == null ? null : declaration.externalEvidence(),
                                    declaration == null ? null : declaration.owner(),
                                    declaration == null ? null : declaration.decidedBy(),
                                    declaration == null ? null : stamp(declaration.decidedAt()),
                                    declaration == null ? null : stamp(declaration.reviewDueAt()),
                                    scope == null ? "estate" : scope.kind(),
                                    scope == null ? null : String.valueOf(scope.id()),
                                    scope == null ? null : scope.name(),
                                    scope == null ? null : String.valueOf(scope.partial()))
                            .map(OwaspGridCsv::quote)
                            .collect(Collectors.joining(",")))
                    .append(ROW_TERMINATOR);
        }
        return csv.toString();
    }

    private static String nameOf(Enum<?> value) {
        return value == null ? null : value.name();
    }

    private static String stamp(Instant instant) {
        return instant == null ? null : instant.toString();
    }

    /** Neutralized, then quoted unconditionally with quotes doubled — see {@code TriageHistoryCsv} for why both. */
    private static String quote(String value) {
        String safe = value == null ? "" : SpreadsheetCells.neutralize(value);
        return '"' + safe.replace("\"", "\"\"") + '"';
    }
}
