package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a template version read through a confirmed layout")
class TemplateVersionTest {

    private static Map<ChecklistColumn, String> columns(String... pairs) {
        Map<ChecklistColumn, String> columns = new EnumMap<>(ChecklistColumn.class);
        for (int i = 0; i < pairs.length; i += 2) {
            columns.put(ChecklistColumn.valueOf(pairs[i]), pairs[i + 1]);
        }
        return columns;
    }

    private static final Map<ChecklistColumn, String> SEVEN = columns("DOMAIN", "A", "OBJECTIVE", "B", "CONTROL", "C",
            "CONTACT", "D", "KPI", "E", "ANSWER", "F", "COMMENT", "G");

    private static ChecklistLayout layout(Map<ChecklistColumn, String> columns, int first, int last) {
        return new ChecklistLayout("Checklist", columns, first, last, Map.of(), AnswerWords.of("Done", "Not done"));
    }

    private static TemplateVersion read(Workbook workbook, Map<ChecklistColumn, String> columns, int first, int last) {
        return TemplateVersion.read(workbook, layout(columns, first, last));
    }

    private static Workbook checklist(String rows) {
        return new XlsxFixture().put("xl/worksheets/sheet2.xml", XlsxFixture.sheet(rows, "")).read();
    }

    private static String cell(String reference, String text) {
        return "<c r=\"" + reference + "\" t=\"inlineStr\"><is><t>" + text + "</t></is></c>";
    }

    @Test
    @DisplayName("fills the domain and the objective down from the first row of their group")
    void fillDown() {
        TemplateVersion version = read(new XlsxFixture().read(), SEVEN, 7, 11);

        assertThat(version.items())
                .extracting(ChecklistItem::domain, ChecklistItem::objective, ChecklistItem::row)
                .containsExactly(
                        tuple("Identity", "1. Accounts are personal", 7),
                        tuple("Identity", "1. Accounts are personal", 8),
                        tuple("Identity", "2. Sessions expire", 9),
                        tuple("Supply chain", "3. Dependencies are known", 10),
                        tuple("Supply chain", "3. Dependencies are known", 11));
        assertThat(version.items()).extracting(ChecklistItem::position).containsExactly(1, 2, 3, 4, 5);
        assertThat(version.items().get(1).kpi()).isEqualTo("No shared account in the directory");
        assertThat(version.items().get(0).contact()).isEqualTo("Security officer");
    }

    @Test
    @DisplayName("an objective does not carry into a new domain that writes none of its own")
    void objectiveStopsAtANewDomain() {
        Workbook workbook = checklist("<row r=\"2\">" + cell("A2", "First") + cell("B2", "Its objective") + cell("C2", "One") + "</row>"
                + "<row r=\"3\">" + cell("A3", "Second") + cell("C3", "Two") + "</row>"
                + "<row r=\"4\">" + cell("C4", "Three") + "</row>");

        TemplateVersion version = read(workbook, SEVEN, 2, 4);

        assertThat(version.items()).extracting(ChecklistItem::objective).containsExactly("Its objective", "", "");
        assertThat(version.items()).extracting(ChecklistItem::domain).containsExactly("First", "Second", "Second");
    }

    @Test
    @DisplayName("a row without a control is not an item, and the domain written on it still carries down")
    void headingRows() {
        Workbook workbook = checklist("<row r=\"2\">" + cell("A2", "Heading only") + "</row>"
                + "<row r=\"3\">" + cell("C3", "One") + "</row>"
                + "<row r=\"5\">" + cell("C5", "Two") + "</row>");

        TemplateVersion version = read(workbook, SEVEN, 2, 5);

        assertThat(version.items()).extracting(ChecklistItem::control).containsExactly("One", "Two");
        assertThat(version.items()).extracting(ChecklistItem::domain).containsOnly("Heading only");
        assertThat(version.items()).extracting(ChecklistItem::row).containsExactly(3, 5);
    }

    @Test
    @DisplayName("an item is keyed by its control's text, or by the id column when the layout names one")
    void keys() {
        Workbook workbook = checklist("<row r=\"2\">" + cell("C2", "One") + cell("H2", "AC-1") + "</row>"
                + "<row r=\"3\">" + cell("C3", "Two") + cell("H3", "AC-2") + "</row>");
        Map<ChecklistColumn, String> withId = new EnumMap<>(SEVEN);
        withId.put(ChecklistColumn.ID, "H");

        assertThat(read(workbook, SEVEN, 2, 3).items()).extracting(ChecklistItem::key)
                .containsExactly(ItemKey.fromControl("One"), ItemKey.fromControl("Two"));
        assertThat(read(workbook, withId, 2, 3).items()).extracting(ChecklistItem::key)
                .containsExactly(ItemKey.fromId("AC-1"), ItemKey.fromId("AC-2"));
    }

    @Test
    @DisplayName("refuses an item row without an id when the id column identifies the items")
    void missingId() {
        Workbook workbook = checklist("<row r=\"2\">" + cell("C2", "One") + "</row>");
        Map<ChecklistColumn, String> withId = new EnumMap<>(SEVEN);
        withId.put(ChecklistColumn.ID, "H");

        assertThatThrownBy(() -> read(workbook, withId, 2, 2))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("Row 2 has a control and no id");
    }

    @Test
    @DisplayName("refuses two lines that read as one item, naming both rows")
    void duplicateControls() {
        Workbook workbook = checklist("<row r=\"2\">" + cell("C2", "Backups are tested.") + "</row>"
                + "<row r=\"3\">" + cell("C3", "backups   are TESTED.") + "</row>");

        assertThatThrownBy(() -> read(workbook, SEVEN, 2, 3))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("Rows 2 and 3 read as the same item");
    }

    @Test
    @DisplayName("refuses item rows holding no control, and a sheet the workbook does not have")
    void empty() {
        Workbook workbook = new XlsxFixture().read();

        assertThatThrownBy(() -> read(workbook, SEVEN, 20, 30))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("the template has no item");
        assertThatThrownBy(() -> TemplateVersion.read(workbook, new ChecklistLayout("Elsewhere", SEVEN, 7, 11, Map.of(),
                        AnswerWords.of("Done", "Not done"))))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("which the workbook does not have");
    }

    @Test
    @DisplayName("refuses a control longer than an item holds, rather than cutting it")
    void tooLong() {
        Workbook workbook = checklist("<row r=\"2\">" + cell("C2", "x".repeat(ChecklistItem.MAX_CONTROL + 1)) + "</row>");

        assertThatThrownBy(() -> read(workbook, SEVEN, 2, 2))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("Row 2: the control is longer than " + ChecklistItem.MAX_CONTROL);
    }

    @Test
    @DisplayName("the items are the version's, in order, one per row")
    void itemsInOrder() {
        TemplateVersion version = read(new XlsxFixture().read(), SEVEN, 7, 11);
        ChecklistItem first = version.items().getFirst();

        assertThatThrownBy(() -> new TemplateVersion(version.sourceSha256(), version.layout(), List.of(first, first.withKey(
                ItemKey.fromControl("other")))))
                .hasMessageContaining("numbered");
    }
}
