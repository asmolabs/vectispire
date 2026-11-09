package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.EnumMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a confirmed layout")
class ChecklistLayoutTest {

    private static final AnswerWords WORDS = AnswerWords.of("Done", "Not done");

    private static Map<ChecklistColumn, String> required() {
        Map<ChecklistColumn, String> columns = new EnumMap<>(ChecklistColumn.class);
        columns.put(ChecklistColumn.CONTROL, "c");
        columns.put(ChecklistColumn.ANSWER, "F");
        columns.put(ChecklistColumn.COMMENT, "g");
        return columns;
    }

    private static CellRef at(String reference) {
        return CellRef.parse(reference).orElseThrow();
    }

    @Test
    @DisplayName("keeps the column letters upper case and answers their index")
    void letters() {
        ChecklistLayout layout = new ChecklistLayout("Checklist", required(), 7, 11, Map.of(), WORDS);

        assertThat(layout.columns()).containsEntry(ChecklistColumn.CONTROL, "C").containsEntry(ChecklistColumn.COMMENT, "G");
        assertThat(layout.column(ChecklistColumn.ANSWER)).contains(6);
        assertThat(layout.column(ChecklistColumn.KPI)).isEmpty();
    }

    @Test
    @DisplayName("needs a control, an answer and a comment column, each its own")
    void requiredColumns() {
        for (ChecklistColumn column : new ChecklistColumn[] {ChecklistColumn.CONTROL, ChecklistColumn.ANSWER, ChecklistColumn.COMMENT}) {
            Map<ChecklistColumn, String> columns = required();
            columns.remove(column);
            assertThatThrownBy(() -> new ChecklistLayout("Checklist", columns, 7, 11, Map.of(), WORDS))
                    .isInstanceOf(InvalidTemplateException.class)
                    .hasMessageContaining("no " + column.wireName() + " column");
        }
        Map<ChecklistColumn, String> shared = required();
        shared.put(ChecklistColumn.KPI, "f");
        assertThatThrownBy(() -> new ChecklistLayout("Checklist", shared, 7, 11, Map.of(), WORDS))
                .hasMessageContaining("are both column F");
        Map<ChecklistColumn, String> wrong = required();
        wrong.put(ChecklistColumn.KPI, "E1");
        assertThatThrownBy(() -> new ChecklistLayout("Checklist", wrong, 7, 11, Map.of(), WORDS))
                .hasMessageContaining("no column's letters");
    }

    @Test
    @DisplayName("refuses item rows that are no range, or more rows than anyone answers")
    void rows() {
        assertThatThrownBy(() -> new ChecklistLayout("Checklist", required(), 11, 7, Map.of(), WORDS))
                .hasMessageContaining("no range of a sheet");
        assertThatThrownBy(() -> new ChecklistLayout("Checklist", required(), 1, ChecklistLayout.MAX_ITEM_ROWS + 1, Map.of(),
                WORDS))
                .hasMessageContaining("more than " + ChecklistLayout.MAX_ITEM_ROWS);
        assertThatThrownBy(() -> new ChecklistLayout(" ", required(), 7, 11, Map.of(), WORDS)).hasMessageContaining("no sheet");
    }

    @Test
    @DisplayName("refuses a header cell among the item rows, and two header entries written into one cell")
    void header() {
        assertThatThrownBy(() -> new ChecklistLayout("Checklist", required(), 7, 11,
                Map.of(HeaderCell.Field.AUTHOR, new HeaderCell(at("A8"), at("B8"))), WORDS))
                .hasMessageContaining("lies among the item rows");
        assertThatThrownBy(() -> new ChecklistLayout("Checklist", required(), 7, 11, Map.of(
                HeaderCell.Field.AUTHOR, new HeaderCell(at("A3"), at("B3")),
                HeaderCell.Field.PRODUCT, new HeaderCell(at("C3"), at("B3"))), WORDS))
                .hasMessageContaining("are both written into B3");
        assertThatThrownBy(() -> new HeaderCell(at("A1"), at("A1"))).hasMessageContaining("cannot be its label");
    }

    @Test
    @DisplayName("cell references are read as a person writes them, and refused past the grid")
    void references() {
        assertThat(CellRef.parse("$B$12")).contains(new CellRef(2, 12));
        assertThat(CellRef.parse("xfd1048576")).contains(new CellRef(CellRef.MAX_COLUMN, CellRef.MAX_ROW));
        assertThat(CellRef.parse("XFE1")).isEmpty();
        assertThat(CellRef.parse("A0")).isEmpty();
        assertThat(CellRef.parse("A")).isEmpty();
        assertThat(CellRef.parse("12")).isEmpty();
        assertThat(CellRef.letters(28)).isEqualTo("AB");
        assertThat(new CellRef(28, 3)).hasToString("AB3");
        assertThat(CellRange.parse("C5:A1")).contains(new CellRange(at("A1"), at("C5")));
    }
}
