package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Where a template's checklist lives in its workbook, as the importer confirmed it: the sheet, the
 * column of each field, the rows holding the items, the header's cells and the answer words.
 *
 * <p><b>Confirmed, never inferred at use.</b> The reader proposes one ({@link LayoutProposal}); a
 * person corrects it; this is what is stored with the version, and the renderer reads nothing else
 * (decision 0032 §3). A second guess made at rendering time could land on another column than the
 * one the importer saw, and write answers into the KPI.
 *
 * @param columns each named column's letters, upper case — {@code CONTROL}, {@code ANSWER} and
 *     {@code COMMENT} always, the others when the template has them
 * @param header the header entries the template has; a template without a product cell has none
 */
public record ChecklistLayout(
        String sheet,
        Map<ChecklistColumn, String> columns,
        int firstItemRow,
        int lastItemRow,
        Map<HeaderCell.Field, HeaderCell> header,
        AnswerWords answers) {

    /** Excel's own limit on a sheet's name. */
    public static final int MAX_SHEET_NAME = 31;

    /** A checklist longer than this is a catalogue; nobody answers it line by line. */
    public static final int MAX_ITEM_ROWS = 5_000;

    public ChecklistLayout {
        String name = sheet == null ? "" : sheet;
        if (name.isBlank() || name.length() > MAX_SHEET_NAME) {
            throw new InvalidTemplateException("The layout names no sheet, or one longer than a sheet name can be.");
        }
        Objects.requireNonNull(answers, "answers");
        columns = normalized(Objects.requireNonNull(columns, "columns"));
        for (ChecklistColumn column : ChecklistColumn.values()) {
            if (column.required() && !columns.containsKey(column)) {
                throw new InvalidTemplateException("The layout names no " + column.wireName() + " column.");
            }
        }
        if (firstItemRow < 1 || lastItemRow > CellRef.MAX_ROW || firstItemRow > lastItemRow) {
            throw new InvalidTemplateException("The item rows run from " + firstItemRow + " to " + lastItemRow
                    + ", which is no range of a sheet.");
        }
        if (lastItemRow - firstItemRow + 1 > MAX_ITEM_ROWS) {
            throw new InvalidTemplateException("The item rows span more than " + MAX_ITEM_ROWS + " rows.");
        }
        Map<HeaderCell.Field, HeaderCell> fields = new EnumMap<>(HeaderCell.Field.class);
        fields.putAll(Objects.requireNonNull(header, "header"));
        Map<CellRef, HeaderCell.Field> taken = new HashMap<>();
        for (Map.Entry<HeaderCell.Field, HeaderCell> entry : fields.entrySet()) {
            for (CellRef cell : new CellRef[] {entry.getValue().label(), entry.getValue().value()}) {
                // A header cell inside the item block would be overwritten by an answer, or overwrite one.
                if (cell.row() >= firstItemRow && cell.row() <= lastItemRow) {
                    throw new InvalidTemplateException("The " + entry.getKey().wireName() + " header cell " + cell
                            + " lies among the item rows.");
                }
            }
            HeaderCell.Field other = taken.putIfAbsent(entry.getValue().value(), entry.getKey());
            if (other != null) {
                throw new InvalidTemplateException("The " + other.wireName() + " and the " + entry.getKey().wireName()
                        + " are both written into " + entry.getValue().value() + ".");
            }
        }
        header = Collections.unmodifiableMap(fields);
    }

    /** The index of a named column, from 1; empty when the template has no such column. */
    public Optional<Integer> column(ChecklistColumn column) {
        return Optional.ofNullable(columns.get(column)).flatMap(CellRef::column);
    }

    public boolean offersNotApplicable() {
        return answers.offersNotApplicable();
    }

    private static Map<ChecklistColumn, String> normalized(Map<ChecklistColumn, String> given) {
        Map<ChecklistColumn, String> columns = new EnumMap<>(ChecklistColumn.class);
        Map<Integer, ChecklistColumn> taken = new HashMap<>();
        for (Map.Entry<ChecklistColumn, String> entry : given.entrySet()) {
            ChecklistColumn column = Objects.requireNonNull(entry.getKey(), "column");
            int index = CellRef.column(entry.getValue()).orElseThrow(() -> new InvalidTemplateException("The "
                    + column.wireName() + " column is \"" + entry.getValue() + "\", which is no column's letters."));
            ChecklistColumn other = taken.putIfAbsent(index, column);
            if (other != null) {
                throw new InvalidTemplateException("The " + other.wireName() + " and the " + column.wireName()
                        + " are both column " + CellRef.letters(index) + ".");
            }
            columns.put(column, CellRef.letters(index).toUpperCase(Locale.ROOT));
        }
        return Collections.unmodifiableMap(columns);
    }
}
