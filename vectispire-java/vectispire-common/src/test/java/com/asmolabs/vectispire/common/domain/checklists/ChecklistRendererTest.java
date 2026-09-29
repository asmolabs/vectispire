package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The filled workbook (decision 0032 §10), against a template generated part by part from invented
 * controls ({@link XlsxFixture}): an {@code x14} validation extension, a {@code TODAY()} date, a cell
 * comment and its drawing, shared strings — the parts a spreadsheet library would have re-saved in its
 * own image.
 */
@DisplayName("the checklist renderer")
class ChecklistRendererTest {

    private static final Instant SIGNED = Instant.parse("2026-09-29T12:00:00Z");
    private static final String SHEET = "xl/worksheets/sheet2.xml";

    private static final String CALC_CHAIN = """
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <calcChain xmlns="%s"><c r="B2" i="2"/></calcChain>""".formatted(XlsxFixture.MAIN);

    static ChecklistLayout layout() {
        return layout(Map.of(
                HeaderCell.Field.DATE, new HeaderCell(at("A2"), at("B2")),
                HeaderCell.Field.PRODUCT, new HeaderCell(at("A3"), at("B3")),
                HeaderCell.Field.AUTHOR, new HeaderCell(at("A4"), at("B4"))));
    }

    static ChecklistLayout layout(Map<HeaderCell.Field, HeaderCell> header) {
        Map<ChecklistColumn, String> columns = new LinkedHashMap<>();
        columns.put(ChecklistColumn.DOMAIN, "A");
        columns.put(ChecklistColumn.OBJECTIVE, "B");
        columns.put(ChecklistColumn.CONTROL, "C");
        columns.put(ChecklistColumn.CONTACT, "D");
        columns.put(ChecklistColumn.KPI, "E");
        columns.put(ChecklistColumn.ANSWER, "F");
        columns.put(ChecklistColumn.COMMENT, "G");
        return new ChecklistLayout("Checklist", columns, 7, 11, header, AnswerWords.of("Done", "Not done"));
    }

    private static CellRef at(String reference) {
        return CellRef.parse(reference).orElseThrow();
    }

    /** A signed statement over the fixture's five lines: yes, no, yes on no data, yes measured, unanswered. */
    static ChecklistStatement statement(byte[] template, boolean signed) {
        Instant answered = Instant.parse("2026-09-20T08:30:00Z");
        List<ChecklistStatement.Line> lines = new ArrayList<>();
        lines.add(line(1, 7, answer(1, "yes", null, answered), null, "not_measured_here", List.of(
                new ChecklistStatement.Proof(10, "link", "https://wiki.example.invalid/accounts", null, null, null, null,
                        LocalDate.parse("2026-09-01"), null, "developer", answered, null, null),
                new ChecklistStatement.Proof(11, "link", "https://wiki.example.invalid/withdrawn", null, null, null, null,
                        LocalDate.parse("2026-08-01"), null, "developer", answered, "developer", answered))));
        lines.add(line(2, 8, answer(2, "no", "Two service accounts remain & <are> tracked.", answered), null,
                "not_measured_here", List.of()));
        lines.add(line(3, 9, answer(3, "yes", "The pipeline is not scanned yet.", answered),
                measured("no_data", "never_examined", "No repository has been examined."), "declared_not_measured",
                List.of(new ChecklistStatement.Proof(12, "file", null, "sessions.pdf", "application/pdf", 3L, "ab".repeat(32),
                        LocalDate.parse("2026-09-10"), LocalDate.parse("2027-09-10"), "developer", answered, null, null))));
        lines.add(line(4, 10, answer(4, "yes", null, answered), measured("pass", null, "2 repositories, SBOM within 7 days."),
                "consistent", List.of()));
        lines.add(line(5, 11, null, null, "not_measured_here", List.of()));
        return new ChecklistStatement(ChecklistStatement.FORM, signed ? "signed_off" : "draft", signed,
                new ChecklistStatement.Project(42, "Checkout"), 3,
                new ChecklistStatement.Template("release", "Release checklist", 2, "2026 edition", Digests.sha256Hex(template)),
                new ChecklistStatement.Header("Checkout", "developer", signed ? SIGNED : null),
                new ChecklistStatement.Act("developer", Instant.parse("2026-09-18T09:00:00Z")),
                signed ? new ChecklistStatement.Act("developer", Instant.parse("2026-09-28T09:00:00Z")) : null,
                signed ? new ChecklistStatement.Act("ciso", SIGNED) : null,
                signed ? Boolean.TRUE : null, "1.2.3", signed ? SIGNED : Instant.parse("2026-09-29T13:00:00Z"), lines);
    }

    private static ChecklistStatement.Line line(int position, int row, ChecklistStatement.Answer answer,
            ChecklistStatement.Measured measured, String reconciliation, List<ChecklistStatement.Proof> proofs) {
        return new ChecklistStatement.Line(100 + position, "key-" + position, position, row, "Domain", "Objective",
                "Control " + position, "Contact", "", "d".repeat(64), "link_or_file", null, answer,
                answer == null ? List.of() : List.of(answer), measured, reconciliation, proofs);
    }

    private static ChecklistStatement.Answer answer(long id, String value, String comment, Instant at) {
        return new ChecklistStatement.Answer(id, value, value, comment, "developer", at, null, null, null, false);
    }

    private static ChecklistStatement.Measured measured(String outcome, String reason, String summary) {
        return new ChecklistStatement.Measured("sign_off", "dependency_analysis", "r".repeat(64), null, outcome, reason,
                Instant.parse("2026-09-28T00:00:00Z"), SIGNED, summary, "e".repeat(64), null);
    }

    private static byte[] render(XlsxFixture fixture, boolean signed) {
        byte[] template = fixture.bytes();
        return ChecklistRenderer.render(template, layout(), statement(template, signed));
    }

    // ------------------------------------------------------------------ the parts

    @Nested
    @DisplayName("the template's own bytes")
    class TheTemplatesBytes {

        @Test
        @DisplayName("every part not rewritten is the template's, byte for byte, shared strings and comments included")
        void untouchedParts() {
            XlsxFixture fixture = new XlsxFixture();
            Map<String, byte[]> before = entries(fixture.bytes());
            Map<String, byte[]> after = entries(render(fixture, true));

            List<String> rewritten = List.of("[Content_Types].xml", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", SHEET);
            for (Map.Entry<String, byte[]> part : before.entrySet()) {
                if (!rewritten.contains(part.getKey())) {
                    assertThat(after.get(part.getKey())).as(part.getKey()).isEqualTo(part.getValue());
                }
            }
            assertThat(after.keySet()).as("the entries in their order, the added sheet last")
                    .startsWith(before.keySet().toArray(String[]::new))
                    .endsWith("xl/worksheets/sheet4.xml")
                    .hasSize(before.size() + 1);
        }

        @Test
        @DisplayName("inside the rewritten parts, only the cells written and the added sheet's lines differ")
        void onlyTheCellsWritten() {
            XlsxFixture fixture = new XlsxFixture();
            Map<String, String> before = texts(fixture.bytes());
            Map<String, String> after = texts(render(fixture, true));

            String sheet = after.get(SHEET);
            // The validation extension, the merged title, the drawing's link and the cells not written are
            // the template's text, where they were.
            String extension = before.get(SHEET).substring(before.get(SHEET).indexOf("<mergeCells"));
            assertThat(sheet).endsWith(extension);
            assertThat(sheet).contains("<c r=\"C7\" t=\"s\"><v>14</v></c>")
                    .contains("<c r=\"C11\" t=\"inlineStr\"><is><t>Critical vulnerabilities are fixed within 30 days &amp; "
                            + "tracked.</t></is></c>");
            // The styled empty product cell keeps its style; the answers are inline strings.
            assertThat(sheet).contains("<c r=\"B3\" s=\"1\" t=\"inlineStr\"><is><t xml:space=\"preserve\">Checkout</t></is></c>")
                    .contains("<c r=\"F7\" t=\"inlineStr\"><is><t xml:space=\"preserve\">Done</t></is></c>")
                    .contains("<c r=\"G8\" t=\"inlineStr\"><is><t xml:space=\"preserve\">Two service accounts remain &amp; "
                            + "&lt;are&gt; tracked.</t></is></c>");

            assertThat(after.get("xl/workbook.xml")).isEqualTo(before.get("xl/workbook.xml").replace("</sheets>",
                    "<sheet name=\"Evidence\" sheetId=\"4\" r:id=\"rId5\"/></sheets>"));
            assertThat(after.get("xl/_rels/workbook.xml.rels")).isEqualTo(before.get("xl/_rels/workbook.xml.rels")
                    .replace("</Relationships>", "<Relationship Id=\"rId5\" Type=\"" + XlsxFixture.REL + "/worksheet\" "
                            + "Target=\"worksheets/sheet4.xml\"/></Relationships>"));
            assertThat(after.get("[Content_Types].xml")).isEqualTo(before.get("[Content_Types].xml").replace("</Types>",
                    "<Override PartName=\"/xl/worksheets/sheet4.xml\" ContentType=\""
                            + ChecklistRenderer.WORKSHEET_CONTENT_TYPE + "\"/></Types>"));
        }

        @Test
        @DisplayName("a revision renders to the same bytes twice")
        void deterministic() {
            XlsxFixture fixture = new XlsxFixture();
            byte[] template = fixture.bytes();
            ChecklistStatement statement = statement(template, true);
            byte[] rendered = ChecklistRenderer.render(template, layout(), statement);
            assertThat(ChecklistRenderer.render(template, layout(), statement)).isEqualTo(rendered);
            // Two renderings a second apart would still agree on a clock's time, which DOS dates to two
            // seconds: the date itself is the fixed one.
            try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(rendered))) {
                for (ZipEntry entry = in.getNextEntry(); entry != null; entry = in.getNextEntry()) {
                    assertThat(entry.getTimeLocal()).as(entry.getName()).isEqualTo(DocumentZip.ENTRY_TIME);
                    assertThat(entry.getExtra()).as(entry.getName()).isNull();
                }
            } catch (IOException unreadable) {
                throw new UncheckedIOException(unreadable);
            }
        }
    }

    // ------------------------------------------------------------------ read back

    @Nested
    @DisplayName("the workbook, read back")
    class ReadBack {

        @Test
        @DisplayName("answers in the template's words, the header written, the validation extension still there")
        void theCells() {
            Workbook read = Workbook.read(render(new XlsxFixture(), true), 10L * 1024 * 1024);
            Sheet checklist = read.sheet("Checklist").orElseThrow();

            assertThat(text(checklist, "F7")).isEqualTo("Done");
            assertThat(text(checklist, "F8")).isEqualTo("Not done");
            assertThat(text(checklist, "G8")).isEqualTo("Two service accounts remain & <are> tracked.");
            assertThat(checklist.cells()).as("an unanswered line holds nothing").doesNotContainKey(at("F11"));
            assertThat(text(checklist, "B3")).isEqualTo("Checkout");
            assertThat(text(checklist, "B4")).isEqualTo("developer");
            assertThat(text(checklist, "C9")).as("a shared string still resolves")
                    .isEqualTo("An idle session ends after fifteen minutes.");
            assertThat(checklist.validations()).singleElement().satisfies(validation -> {
                assertThat(validation.fromExtension()).isTrue();
                assertThat(read.listValues(validation, checklist)).containsExactly("Done", "Not done");
            });
            assertThat(read.sheets()).extracting(Sheet::name)
                    .containsExactly("Instructions", "Checklist", "Values", ChecklistRenderer.EVIDENCE_SHEET);
        }

        @Test
        @DisplayName("the date is the sign-off instant as a value, the formula gone and the calculation chain with it")
        void theDate() {
            XlsxFixture fixture = withCalcChain(new XlsxFixture());
            byte[] rendered = render(fixture, true);
            Sheet checklist = Workbook.read(rendered, 10L * 1024 * 1024).sheet("Checklist").orElseThrow();

            // 2026-09-29 is day 46294 of the 1900 system; noon is half a day.
            assertThat(checklist.cells().get(at("B2"))).isEqualTo(new CellValue.Number("46294.5"));
            assertThat(texts(rendered).get(SHEET)).contains("<c r=\"B2\" s=\"3\"><v>46294.5</v></c>").doesNotContain("TODAY");
            Map<String, String> parts = texts(rendered);
            assertThat(parts).doesNotContainKey("xl/calcChain.xml");
            assertThat(parts.get("[Content_Types].xml")).doesNotContain("calcChain");
            assertThat(parts.get("xl/_rels/workbook.xml.rels")).doesNotContain("calcChain");
        }

        @Test
        @DisplayName("with no formula removed, the calculation chain stays")
        void theChainStaysWithItsFormulas() {
            XlsxFixture fixture = withCalcChain(new XlsxFixture());
            // The date written somewhere else: the formula in B2 stays, and so does the chain naming it.
            byte[] template = fixture.bytes();
            ChecklistLayout elsewhere = layout(Map.of(HeaderCell.Field.DATE, new HeaderCell(at("A5"), at("B5"))));
            Map<String, String> parts = texts(ChecklistRenderer.render(template, elsewhere, statement(template, true)));

            assertThat(parts.get("xl/calcChain.xml")).isEqualTo(CALC_CHAIN);
            assertThat(parts.get(SHEET)).contains("<f>TODAY()</f>")
                    .as("row 5, which the template does not have, is created between rows 4 and 6")
                    .contains("</row><row r=\"5\"><c r=\"B5\"><v>46294.5</v></c></row><row r=\"6\">");
        }

        @Test
        @DisplayName("a 1904 workbook counts its days from 1904")
        void date1904() {
            assertThat(ChecklistRenderer.serial(SIGNED, true)).isEqualTo("44832.5");
            assertThat(ChecklistRenderer.serial(Instant.parse("2026-09-29T00:00:00Z"), false)).isEqualTo("46294");
        }
    }

    // ------------------------------------------------------------------ drafts and the evidence sheet

    @Nested
    @DisplayName("the evidence sheet")
    class TheEvidenceSheet {

        @Test
        @DisplayName("a draft says it is not signed off, and its date cell holds no date")
        void aDraft() {
            byte[] rendered = render(new XlsxFixture(), false);
            Workbook read = Workbook.read(rendered, 10L * 1024 * 1024);
            Sheet evidence = read.sheet(ChecklistRenderer.EVIDENCE_SHEET).orElseThrow();

            assertThat(text(evidence, "A1")).isEqualTo("Draft — not signed off");
            assertThat(read.sheet("Checklist").orElseThrow().cells()).as("no formula dating it now, no date")
                    .doesNotContainKey(at("B2"));
            assertThat(texts(rendered).get(SHEET)).contains("<c r=\"B2\" s=\"3\"/>");
            assertThat(texts(rendered).get("xl/worksheets/sheet4.xml")).contains("Four-eyes rule")
                    .contains("not signed off: no rule has applied yet");
        }

        @Test
        @DisplayName("one row per line: answer, author, measurement, reconciliation, proofs; then who stands behind it")
        void theRows() {
            Sheet evidence = Workbook.read(render(new XlsxFixture(), true), 10L * 1024 * 1024)
                    .sheet(ChecklistRenderer.EVIDENCE_SHEET).orElseThrow();

            assertThat(text(evidence, "A1")).startsWith("Signed off by ciso at 2026-09-29T12:00:00Z");
            assertThat(text(evidence, "A3")).isEqualTo("Line");
            // Line 1: a yes with a link; the withdrawn proof is not among those it rests on.
            assertThat(text(evidence, "C4")).isEqualTo("Done");
            assertThat(text(evidence, "D4")).isEqualTo("developer");
            assertThat(text(evidence, "E4")).isEqualTo("2026-09-20T08:30:00Z");
            assertThat(text(evidence, "F4")).isEqualTo("not measured here");
            assertThat(text(evidence, "J4")).isEqualTo("link https://wiki.example.invalid/accounts, performed on 2026-09-01");
            // Line 3: a yes where the measurement had no data — declared, not measured — with its file's digest.
            assertThat(text(evidence, "F6")).isEqualTo("no data (never examined)");
            assertThat(text(evidence, "G6")).isEqualTo("2026-09-28T00:00:00Z");
            assertThat(text(evidence, "H6")).isEqualTo("declared, not measured");
            assertThat(text(evidence, "I6")).isEqualTo("No repository has been examined. — evidence SHA-256 " + "e".repeat(64));
            assertThat(text(evidence, "J6")).isEqualTo("file sessions.pdf SHA-256 " + "ab".repeat(32)
                    + ", performed on 2026-09-10, valid until 2027-09-10");
            assertThat(text(evidence, "H7")).isEqualTo("consistent");
            assertThat(text(evidence, "C8")).isEqualTo("unanswered");

            Map<String, String> footer = new LinkedHashMap<>();
            evidence.cells().forEach((cell, value) -> {
                if (cell.column() == 1 && cell.row() > 9) {
                    footer.put(value.text(), text(evidence, "B" + cell.row()));
                }
            });
            assertThat(footer).containsEntry("Submitted by", "developer at 2026-09-28T09:00:00Z")
                    .containsEntry("Signed off by", "ciso at 2026-09-29T12:00:00Z")
                    .containsEntry("Four-eyes rule", "required — the signer is none of the revision's authors")
                    .containsEntry("Produced by", "Vectispire 1.2.3 at 2026-09-29T12:00:00Z")
                    .containsKey("Template source SHA-256");
        }
    }

    // ------------------------------------------------------------------ refusals

    @Nested
    @DisplayName("what it refuses")
    class Refusals {

        @Test
        @DisplayName("a template that is not the version's, and one past the reader's guards")
        void notTheTemplate() {
            byte[] template = new XlsxFixture().bytes();
            ChecklistStatement statement = statement(template, true);
            byte[] other = new XlsxFixture().put("xl/worksheets/sheet1.xml", XlsxFixture.sheet("", "")).bytes();
            assertThatThrownBy(() -> ChecklistRenderer.render(other, layout(), statement))
                    .isInstanceOf(IllegalStateException.class).hasMessageContaining("source SHA-256");

            byte[] doctype = new XlsxFixture().put("xl/worksheets/sheet1.xml",
                    "<?xml version=\"1.0\"?><!DOCTYPE worksheet [<!ENTITY x \"y\">]><worksheet xmlns=\"" + XlsxFixture.MAIN
                            + "\"><sheetData/></worksheet>").bytes();
            assertThatThrownBy(() -> ChecklistRenderer.render(doctype, layout(), statement(doctype, true)))
                    .isInstanceOf(InvalidTemplateException.class);
        }

        @Test
        @DisplayName("a formula other cells share is not overwritten")
        void aSharedFormula() {
            XlsxFixture fixture = new XlsxFixture();
            fixture.put(SHEET, fixture.parts.get(SHEET).replace("<f>TODAY()</f>", "<f t=\"shared\" ref=\"B2:C2\" si=\"0\">TODAY()</f>"));
            assertThatThrownBy(() -> render(fixture, true)).isInstanceOf(InvalidTemplateException.class)
                    .hasMessageContaining("B2").hasMessageContaining("share");
        }
    }

    // ------------------------------------------------------------------ helpers

    private static XlsxFixture withCalcChain(XlsxFixture fixture) {
        fixture.put("xl/calcChain.xml", CALC_CHAIN);
        fixture.put("[Content_Types].xml", fixture.parts.get("[Content_Types].xml").replace("</Types>",
                "<Override PartName=\"/xl/calcChain.xml\" ContentType=\"application/vnd.openxmlformats-officedocument"
                        + ".spreadsheetml.calcChain+xml\"/></Types>"));
        fixture.put("xl/_rels/workbook.xml.rels", fixture.parts.get("xl/_rels/workbook.xml.rels").replace("</Relationships>",
                "<Relationship Id=\"rId9\" Type=\"" + XlsxFixture.REL + "/calcChain\" Target=\"calcChain.xml\"/></Relationships>"));
        return fixture;
    }

    private static String text(Sheet sheet, String reference) {
        return Optional.ofNullable(sheet.cells().get(at(reference))).map(CellValue::text).orElse(null);
    }

    static Map<String, byte[]> entries(byte[] zip) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(zip))) {
            for (ZipEntry entry = in.getNextEntry(); entry != null; entry = in.getNextEntry()) {
                entries.put(entry.getName(), in.readAllBytes());
            }
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
        return entries;
    }

    private static Map<String, String> texts(byte[] zip) {
        Map<String, String> texts = new LinkedHashMap<>();
        entries(zip).forEach((name, bytes) -> texts.put(name, new String(bytes, StandardCharsets.UTF_8)));
        return texts;
    }
}
