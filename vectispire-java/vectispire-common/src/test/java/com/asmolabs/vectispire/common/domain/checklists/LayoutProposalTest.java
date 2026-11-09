package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the layout proposed from a workbook's structure")
class LayoutProposalTest {

    private static CellRef at(String reference) {
        return CellRef.parse(reference).orElseThrow();
    }

    @Test
    @DisplayName("finds the checklist sheet, the header row and the item rows from the answer column's validation")
    void rows() {
        LayoutProposal proposal = LayoutProposal.of(new XlsxFixture().read());

        assertThat(proposal.sheet()).isEqualTo("Checklist");
        assertThat(proposal.columnHeaderRow()).contains(6);
        assertThat(proposal.firstItemRow()).contains(7);
        assertThat(proposal.lastItemRow()).contains(11);
    }

    @Test
    @DisplayName("names the columns by their place: grouped ones first, then control, contact and KPI, answer and comment")
    void columns() {
        LayoutProposal proposal = LayoutProposal.of(new XlsxFixture().read());

        assertThat(proposal.columns()).containsExactlyInAnyOrderEntriesOf(Map.of(
                ChecklistColumn.DOMAIN, "A",
                ChecklistColumn.OBJECTIVE, "B",
                ChecklistColumn.CONTROL, "C",
                ChecklistColumn.CONTACT, "D",
                ChecklistColumn.KPI, "E",
                ChecklistColumn.ANSWER, "F",
                ChecklistColumn.COMMENT, "G"));
        assertThat(proposal.columns()).doesNotContainKey(ChecklistColumn.ID);
    }

    @Test
    @DisplayName("an identifier column in front of the domain is stepped over, and every other column keeps its place")
    void identifierColumnInFront() {
        // The fixture's table moved one column right, an id written on every line in front of it (ID-1…):
        // nothing grouped at the edge read the id as the control and every column after it one off.
        XlsxFixture fixture = new XlsxFixture();
        String sheet = fixture.parts.get("xl/worksheets/sheet2.xml");
        Matcher cells = Pattern.compile("r=\"([A-G])([6-9]|1[01])\"").matcher(sheet);
        sheet = cells.replaceAll(m -> "r=\"" + (char) (m.group(1).charAt(0) + 1) + m.group(2) + "\"");
        sheet = sheet.replace("<row r=\"6\">", "<row r=\"6\"><c r=\"A6\" t=\"inlineStr\"><is><t>ID</t></is></c>");
        for (int row = 7; row <= 11; row++) {
            sheet = sheet.replace("<row r=\"" + row + "\">", "<row r=\"" + row + "\"><c r=\"A" + row
                    + "\" t=\"inlineStr\"><is><t>ID-" + (row - 6) + "</t></is></c>");
        }
        fixture.put("xl/worksheets/sheet2.xml", sheet.replace("<xm:sqref>F7:F11</xm:sqref>", "<xm:sqref>G7:G11</xm:sqref>"));

        LayoutProposal proposal = LayoutProposal.of(fixture.read());

        assertThat(proposal.columns()).containsExactlyInAnyOrderEntriesOf(Map.of(
                ChecklistColumn.DOMAIN, "B",
                ChecklistColumn.OBJECTIVE, "C",
                ChecklistColumn.CONTROL, "D",
                ChecklistColumn.CONTACT, "E",
                ChecklistColumn.KPI, "F",
                ChecklistColumn.ANSWER, "G",
                ChecklistColumn.COMMENT, "H"));
        assertThat(proposal.firstItemRow()).contains(7);
        assertThat(proposal.lastItemRow()).contains(11);
    }

    @Test
    @DisplayName("finds the header cells: the date by its formula, then the product and the author, the merged title aside")
    void header() {
        LayoutProposal proposal = LayoutProposal.of(new XlsxFixture().read());

        assertThat(proposal.header()).containsExactlyInAnyOrderEntriesOf(Map.of(
                HeaderCell.Field.DATE, new HeaderCell(at("A2"), at("B2")),
                HeaderCell.Field.PRODUCT, new HeaderCell(at("A3"), at("B3")),
                HeaderCell.Field.AUTHOR, new HeaderCell(at("A4"), at("B4"))));
    }

    @Test
    @DisplayName("offers the validation list's values as the answer words, and maps none of them")
    void answerValues() {
        LayoutProposal proposal = LayoutProposal.of(new XlsxFixture().read());

        assertThat(proposal.answerValues()).containsExactly("Done", "Not done");
    }

    @Test
    @DisplayName("finds nothing by its words: the same structure under other labels is proposed the same")
    void noVocabulary() {
        XlsxFixture fixture = new XlsxFixture();
        fixture.put("xl/sharedStrings.xml", fixture.parts.get("xl/sharedStrings.xml")
                .replace("<t>Domain</t>", "<t>Zone</t>")
                .replace("<t>Control</t>", "<t>Exigence</t>")
                .replace("<t>Answer</t>", "<t>Réponse</t>")
                .replace("<t>Date</t>", "<t>Le jour</t>"));

        LayoutProposal proposal = LayoutProposal.of(fixture.read());

        assertThat(proposal.columns()).containsEntry(ChecklistColumn.CONTROL, "C").containsEntry(ChecklistColumn.ANSWER, "F");
        assertThat(proposal.header()).containsKey(HeaderCell.Field.DATE);
    }

    @Test
    @DisplayName("without a validation, proposes the longest run below a header row and leaves the answer to the importer")
    void withoutValidation() {
        XlsxFixture fixture = new XlsxFixture();
        String sheet = fixture.parts.get("xl/worksheets/sheet2.xml");
        fixture.put("xl/worksheets/sheet2.xml", sheet.substring(0, sheet.indexOf("<extLst>")) + "</worksheet>");

        LayoutProposal proposal = LayoutProposal.of(fixture.read());

        assertThat(proposal.sheet()).isEqualTo("Checklist");
        assertThat(proposal.columnHeaderRow()).contains(6);
        assertThat(proposal.lastItemRow()).contains(11);
        assertThat(proposal.columns()).doesNotContainKeys(ChecklistColumn.ANSWER, ChecklistColumn.COMMENT);
        assertThat(proposal.answerValues()).isEmpty();
    }

    @Test
    @DisplayName("a workbook without a header row proposes its first sheet and no rows")
    void nothingFound() {
        Workbook workbook = new XlsxFixture()
                .put("xl/worksheets/sheet2.xml", XlsxFixture.sheet("<row r=\"1\"><c r=\"A1\" t=\"s\"><v>1</v></c></row>", ""))
                .put("xl/worksheets/sheet3.xml", XlsxFixture.sheet("", ""))
                .read();

        LayoutProposal proposal = LayoutProposal.of(workbook);

        assertThat(proposal.sheet()).isEqualTo("Instructions");
        assertThat(proposal.columnHeaderRow()).isEmpty();
        assertThatThrownBy(() -> proposal.confirm(AnswerWords.of("Done", "Not done")))
                .isInstanceOf(InvalidTemplateException.class)
                .hasMessageContaining("No item rows");
    }

    @Test
    @DisplayName("confirmed with the importer's words, it reads the fixture's five items")
    void confirm() {
        Workbook workbook = new XlsxFixture().read();
        ChecklistLayout layout = LayoutProposal.of(workbook).confirm(AnswerWords.of("Done", "Not done"));

        TemplateVersion version = TemplateVersion.read(workbook, layout);

        assertThat(version.items()).hasSize(5);
        assertThat(version.layout().offersNotApplicable()).isFalse();
        assertThat(version.sourceSha256()).isEqualTo(workbook.sha256());
    }

    @Test
    @DisplayName("an instruction line above the header, one or two cells wide, is not taken for the header row")
    void proseAbove() {
        XlsxFixture fixture = new XlsxFixture();
        String sheet = fixture.parts.get("xl/worksheets/sheet2.xml");
        fixture.put("xl/worksheets/sheet2.xml", sheet.replace("<row r=\"6\">",
                "<row r=\"5\"><c r=\"A5\" t=\"s\"><v>0</v></c><c r=\"F5\" t=\"s\"><v>10</v></c></row><row r=\"6\">"));

        LayoutProposal proposal = LayoutProposal.of(fixture.read());

        assertThat(proposal.columnHeaderRow()).contains(6);
        assertThat(proposal.header()).doesNotContainValue(new HeaderCell(at("A5"), at("B5")));
        assertThat(Optional.ofNullable(proposal.header().get(HeaderCell.Field.PRODUCT))).contains(new HeaderCell(at("A3"), at("B3")));
    }
}
