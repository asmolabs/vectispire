package com.asmolabs.vectispire.common.domain.exports;

import java.util.regex.Pattern;

/**
 * Formula neutralization, for every CSV this system hands to a spreadsheet.
 *
 * <p><b>One place, because two copies had already become one and a half.</b> The rule lived as a
 * private detail of {@link IssueCsv}; the triage history export, written later beside it, doubled
 * its quotes and nothing else, and served repository names, branches, identifiers and free-text
 * triage comments to auditors as live formulas. A rule every export must apply is not a detail of
 * one of them.
 */
public final class SpreadsheetCells {

    private SpreadsheetCells() {}

    /**
     * The characters by which a spreadsheet decides a cell is a <b>formula</b>.
     *
     * <p>Excel, LibreOffice and Google Sheets evaluate a cell starting with any of them. Tab
     * and carriage return are in the list because Excel skips them before resuming its parse:
     * {@code \t=cmd|…} is evaluated as {@code =cmd|…}.
     */
    private static final Pattern FORMULA_PREFIX = Pattern.compile("^[=+\\-@\\t\\r]");

    /**
     * The value, forced to text when a spreadsheet would evaluate it.
     *
     * <p><b>The content comes from outside the trust boundary</b>: a package name, a file path, a
     * rule identifier or a repository name is chosen by whoever can commit to the target, and a
     * triage comment by whoever can triage. The reader is a security operator or an auditor
     * opening the file in a spreadsheet, which is the entire point of a CSV export.
     *
     * <p>A cell reading {@code =cmd|'/c calc'!A1} executes on open;
     * {@code =HYPERLINK(...&A1&B1)} exfiltrates the neighbouring cells — the rest of the export —
     * to a host of the attacker's choosing, with no prompt at all. A leading apostrophe forces
     * text mode.
     *
     * <p><b>Quoting does not protect</b>: the spreadsheet strips the quotes before evaluating.
     * Neutralization has to come first, and cannot be replaced by it.
     */
    public static String neutralize(String value) {
        return FORMULA_PREFIX.matcher(value).find() ? "'" + value : value;
    }
}
