package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.checklists.ChecklistLayout;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A template version's layout as the importer confirms it and as the API shows it: the checklist's
 * sheet, the column of each field, the rows holding the items, the header's cells and the answer
 * words (decision 0032 §3, steps 1 and 3).
 *
 * <p>Read into a {@code ChecklistLayout} by {@link ChecklistTemplateService}, which refuses in words
 * anything a layout cannot be; the request may leave any part out, and is told which.
 *
 * @param columns column letters by field — {@code control}, {@code answer} and {@code comment}
 *     always; {@code id}, {@code domain}, {@code objective}, {@code contact}, {@code kpi} when the
 *     template has them. An {@code id} column makes its values the items' keys
 * @param header the header's label and value cells by entry — {@code date}, {@code product}, {@code
 *     author} — each only when the template has it
 * @param answers the template's own words for yes and no, and for not applicable when the version
 *     offers it
 */
public record ChecklistLayoutForm(
        String sheet,
        Map<String, String> columns,
        Integer firstItemRow,
        Integer lastItemRow,
        Map<String, HeaderCellForm> header,
        AnswerWordsForm answers) {

    /** A header entry: the label cell the renderer leaves alone and the value cell it writes, {@code B3}. */
    public record HeaderCellForm(String label, String value) {}

    /** @param notApplicable null or blank when the version does not offer "not applicable" */
    public record AnswerWordsForm(String yes, String no, String notApplicable) {}

    public static ChecklistLayoutForm of(ChecklistLayout layout) {
        Map<String, String> columns = new LinkedHashMap<>();
        layout.columns().forEach((column, letters) -> columns.put(column.wireName(), letters));
        Map<String, HeaderCellForm> header = new LinkedHashMap<>();
        layout.header().forEach((field, cell) ->
                header.put(field.wireName(), new HeaderCellForm(cell.label().toString(), cell.value().toString())));
        return new ChecklistLayoutForm(layout.sheet(), columns, layout.firstItemRow(), layout.lastItemRow(), header,
                new AnswerWordsForm(layout.answers().yes(), layout.answers().no(),
                        layout.answers().notApplicable().orElse(null)));
    }
}
