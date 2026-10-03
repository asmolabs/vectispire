package com.asmolabs.vectispire.reportdemo;

import static com.asmolabs.vectispire.reportdemo.Fixtures.column;
import static com.asmolabs.vectispire.reportdemo.Fixtures.labelled;
import static com.asmolabs.vectispire.reportdemo.Fixtures.sheet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.checklists.CellRef;
import com.asmolabs.vectispire.common.domain.checklists.CellValue;
import com.asmolabs.vectispire.common.domain.checklists.Sheet;
import com.asmolabs.vectispire.common.domain.checklists.Workbook;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.TimeZone;
import java.util.stream.StreamSupport;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("the demonstration report plugin")
class ReportDemoTest {

    @Nested
    @DisplayName("the fixtures it is tested on")
    class TheFixtures {

        @Test
        @DisplayName("are exports the published schema accepts")
        void conform() {
            Fixtures.conforms(Fixtures.export("sample.json"));
            Fixtures.conforms(Fixtures.export("empty-project.json"));
            Fixtures.conforms(Fixtures.bytes(laterMinor()));
        }
    }

    @Nested
    @DisplayName("the workbook")
    class TheWorkbook {

        private final Workbook workbook = Fixtures.read(ReportDemo.render(Fixtures.export("sample.json")));

        @Test
        @DisplayName("passes the platform's workbook reader: three sheets, in order")
        void readable() {
            assertThat(workbook.sheets()).extracting(Sheet::name).containsExactly("Summary", "Issues", "Checklists");
        }

        @Test
        @DisplayName("Summary: the project, the requester, the version and the export's instant — never now")
        void summary() {
            Sheet summary = sheet(workbook, "Summary");
            assertThat(labelled(summary, "Project")).isEqualTo("Checkout");
            assertThat(labelled(summary, "Project id")).isEqualTo("3");
            assertThat(labelled(summary, "Solution")).isEqualTo("Payments");
            assertThat(labelled(summary, "Requested by")).isEqualTo("Ada Developer");
            assertThat(labelled(summary, "Vectispire version")).isEqualTo("0.12.0");
            assertThat(labelled(summary, "Exported at")).isEqualTo("2026-10-01T08:30:00Z");
            assertThat(labelled(summary, "Export schema")).isEqualTo("vectispire-project-export 1.0");
            assertThat(labelled(summary, "Issues listed")).isEqualTo("3");
        }

        @Test
        @DisplayName("Summary: one gate line per target, a target never judged said so, and named as the project names it")
        void gate() {
            Sheet summary = sheet(workbook, "Summary");
            assertThat(labelled(summary, "repository checkout-api.git")).isEqualTo("failed");
            assertThat(labelled(summary, "repository checkout-web.git")).isEqualTo("never judged");
            assertThat(labelled(summary, "container checkout/api:2.4.1")).isEqualTo("never judged");
        }

        @Test
        @DisplayName("Summary: every count of the export, and their total")
        void counts() {
            Sheet summary = sheet(workbook, "Summary");
            int total = rowLabelled(summary, "Total");
            assertThat(summary.text(new CellRef(5, total))).isEqualTo("7");
            assertThat(summary.text(new CellRef(1, total - 1))).isEqualTo("vulnerability");
            assertThat(summary.text(new CellRef(3, total - 1))).isEqualTo("resolved");
            assertThat(summary.text(new CellRef(5, total - 1))).isEqualTo("4");
        }

        @Test
        @DisplayName("Issues: one row per issue, in the export's order, triage and remediation included")
        void issues() {
            Sheet issues = sheet(workbook, "Issues");
            assertThat(column(issues, "Id")).containsExactly("1001", "1002", "1003");
            assertThat(column(issues, "Target")).containsExactly("repository checkout-api.git",
                    "repository checkout-api.git", "container checkout/api:2.4.1");
            assertThat(column(issues, "Triage status")).containsExactly("under_review", "", "not_affected");
            assertThat(column(issues, "Decided by")).as("a person with no display name, by account")
                    .containsExactly("Ada Developer", "", "account 9");
            assertThat(column(issues, "Triage comment")).contains("Dead <code> & \"unused\"");
            assertThat(column(issues, "Remediation state")).containsExactly("overdue", "", "");
            assertThat(column(issues, "KEV")).containsExactly("yes", "no", "no");
        }

        @Test
        @DisplayName("Issues: a null stays an empty cell — never a zero the export did not record")
        void nullIsEmpty() {
            Sheet issues = sheet(workbook, "Issues");
            assertThat(column(issues, "CVSS")).containsExactly("10.0", "", "");
            assertThat(column(issues, "Line")).containsExactly("", "12", "3");
            int cvss = columnNumber(issues, "CVSS");
            assertThat(issues.value(new CellRef(cvss, 2))).get().isInstanceOf(CellValue.Number.class);
            assertThat(issues.value(new CellRef(cvss, 3))).as("no cell at all").isEmpty();
        }

        @Test
        @DisplayName("Checklists: one row per line, its answer, who gave it and the proofs still standing")
        void checklists() {
            Sheet checklists = sheet(workbook, "Checklists");
            assertThat(column(checklists, "Line")).containsExactly("SD-01", "SD-02");
            assertThat(column(checklists, "Template")).containsOnly("Secure delivery checklist");
            assertThat(column(checklists, "Answer")).containsExactly("Oui", "");
            assertThat(column(checklists, "Answered by kind")).containsExactly("system", "");
            assertThat(column(checklists, "Evidence")).containsExactly("sbom.json (sha256 aa11)", "");
            assertThat(column(checklists, "Signed")).containsOnly("yes");
        }

        @Test
        @DisplayName("an export with nothing in it is a workbook with headings and nothing under them")
        void empty() {
            Workbook empty = Fixtures.read(ReportDemo.render(Fixtures.export("empty-project.json")));
            assertThat(sheet(empty, "Issues").lastRow()).isEqualTo(1);
            assertThat(sheet(empty, "Checklists").lastRow()).isEqualTo(1);
            assertThat(labelled(sheet(empty, "Summary"), "Requested by")).isEqualTo("account 4");
            assertThat(labelled(sheet(empty, "Summary"), "Vectispire version")).as("not stated, not guessed").isEmpty();
        }
    }

    @Nested
    @DisplayName("the same export gives the same bytes")
    class Determinism {

        @Test
        @DisplayName("twice in a row, and in another time zone")
        void sameBytes() {
            byte[] export = Fixtures.export("sample.json");
            byte[] first = ReportDemo.render(export);
            assertThat(ReportDemo.render(export)).isEqualTo(first);

            TimeZone before = TimeZone.getDefault();
            try {
                TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Kiritimati"));
                assertThat(ReportDemo.render(export)).as("the zip's dates are not the host's").isEqualTo(first);
            } finally {
                TimeZone.setDefault(before);
            }
        }

        @Test
        @DisplayName("the parts in one order, [Content_Types].xml first, each dated 1980-02-01, no macro, no properties")
        void theZip() throws IOException {
            List<String> names = new ArrayList<>();
            try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(
                    ReportDemo.render(Fixtures.export("sample.json"))))) {
                for (ZipEntry entry; (entry = zip.getNextEntry()) != null; ) {
                    names.add(entry.getName());
                    assertThat(entry.getTimeLocal()).isEqualTo(LocalDateTime.of(1980, 2, 1, 0, 0));
                    assertThat(entry.getExtra()).as("no extended timestamp").isNull();
                }
            }
            assertThat(names).containsExactly("[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
                    "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml",
                    "xl/worksheets/sheet3.xml");
        }
    }

    @Nested
    @DisplayName("what it reads, and what it refuses")
    class Reading {

        @Test
        @DisplayName("a later minor, with parts and fields 1.0 does not know, renders as 1.0 does")
        void laterMinor() {
            Workbook later = Fixtures.read(ReportDemo.render(Fixtures.bytes(ReportDemoTest.laterMinor())));
            assertThat(column(sheet(later, "Issues"), "Id")).containsExactly("1001", "1002", "1003");
            assertThat(labelled(sheet(later, "Summary"), "Export schema")).isEqualTo("vectispire-project-export 1.3");
        }

        @Test
        @DisplayName("another major, exit 2 and why on stderr, nothing written")
        void anotherMajor(@TempDir Path directory) throws IOException {
            ObjectNode export = Fixtures.tree("sample.json");
            export.put("schema_version", "2.0");
            Result result = run(directory, Fixtures.bytes(export));
            assertThat(result.code()).isEqualTo(2);
            assertThat(result.stderr()).contains("2.0").contains("reads major 1 only");
            assertThat(result.output()).doesNotExist();
        }

        @Test
        @DisplayName("another schema, or none, exit 2")
        void anotherSchema(@TempDir Path directory) throws IOException {
            ObjectNode export = Fixtures.tree("sample.json");
            export.put("schema", "vectispire-checklist");
            assertThat(run(directory, Fixtures.bytes(export)).code()).isEqualTo(2);
            export.remove("schema");
            assertThat(run(directory, Fixtures.bytes(export)).stderr()).contains("states schema none");
            ObjectNode noVersion = Fixtures.tree("sample.json");
            noVersion.put("schema_version", "1");
            assertThat(run(directory, Fixtures.bytes(noVersion)).code()).isEqualTo(2);
        }

        @Test
        @DisplayName("a part it renders missing is not an empty part: exit 1, never a workbook saying \"no issue\"")
        void missingPart(@TempDir Path directory) throws IOException {
            for (String part : List.of("issues", "gate", "issue_counts", "checklists", "export", "project")) {
                ObjectNode export = Fixtures.tree("sample.json");
                export.remove(part);
                Result result = run(directory, Fixtures.bytes(export));
                assertThat(result.code()).as(part).isEqualTo(1);
                assertThat(result.stderr()).contains("\"" + part + "\"");
                assertThat(result.output()).doesNotExist();
            }
            ObjectNode nulled = Fixtures.tree("sample.json");
            nulled.putNull("issues");
            assertThat(run(directory, Fixtures.bytes(nulled)).code()).isEqualTo(1);
            assertThatThrownBy(() -> ReportDemo.render(Fixtures.bytes(nulled)))
                    .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("\"issues\"");
        }

        @Test
        @DisplayName("not JSON, two values for one key, or something after the document: exit 1")
        void unreadable(@TempDir Path directory) throws IOException {
            assertThat(run(directory, "not json".getBytes(StandardCharsets.UTF_8)).code()).isEqualTo(1);
            String sample = new String(Fixtures.export("sample.json"), StandardCharsets.UTF_8);
            assertThat(run(directory, sample.replaceFirst("\\{", "{\"schema\": \"other\", ")
                    .getBytes(StandardCharsets.UTF_8)).stderr()).contains("Duplicate field");
            assertThat(run(directory, (sample + " {}").getBytes(StandardCharsets.UTF_8)).code()).isEqualTo(1);
            assertThat(run(directory, "[]".getBytes(StandardCharsets.UTF_8)).stderr()).contains("not a JSON object");
        }

        @Test
        @DisplayName("an input that is not there, exit 1; other arguments, exit 64")
        void arguments(@TempDir Path directory) {
            Result missing = run(new String[] {"--in", directory.resolve("absent.json").toString(), "--out",
                    directory.resolve("summary.xlsx").toString()});
            assertThat(missing.code()).isEqualTo(1);
            assertThat(missing.stderr()).contains("could not be read");
            assertThat(run(new String[] {"in.json", "out.xlsx"}).code()).isEqualTo(64);
        }

        @Test
        @DisplayName("an output that is a link is not written through")
        void outputLink(@TempDir Path directory) throws IOException {
            Path target = Files.writeString(directory.resolve("elsewhere"), "untouched");
            Path input = Files.write(directory.resolve("export.json"), Fixtures.export("sample.json"));
            Path output = Files.createSymbolicLink(directory.resolve("summary.xlsx"), target);
            Result result = run(new String[] {"--in", input.toString(), "--out", output.toString()});
            assertThat(result.code()).isEqualTo(1);
            assertThat(Files.readString(target)).isEqualTo("untouched");
        }

        @Test
        @DisplayName("written: exit 0, the file the platform reads back, nothing on stderr")
        void written(@TempDir Path directory) throws IOException {
            Result result = run(directory, Fixtures.export("sample.json"));
            assertThat(result.code()).isZero();
            assertThat(result.stderr()).isEmpty();
            assertThat(Files.readAllBytes(result.output())).isEqualTo(ReportDemo.render(Fixtures.export("sample.json")));
        }
    }

    @Nested
    @DisplayName("text a workbook cannot hold as it is")
    class Text {

        @Test
        @DisplayName("past Excel's 32,767 characters, cut and said so — the reader would refuse the whole file")
        void longText() {
            ObjectNode export = Fixtures.tree("sample.json");
            String comment = "x".repeat(40_000);
            ((ObjectNode) export.withArray("issues").get(0).path("triage")).put("comment", comment);
            Workbook workbook = Fixtures.read(ReportDemo.render(Fixtures.bytes(export)));
            String cell = column(sheet(workbook, "Issues"), "Triage comment").getFirst();
            assertThat(cell).hasSizeLessThanOrEqualTo(32_767).endsWith("[cut: 40000 characters in the export]");
        }

        @Test
        @DisplayName("a control character XML cannot carry, a lone surrogate: replaced, the workbook still opens")
        void controlCharacters() {
            ObjectNode export = Fixtures.tree("sample.json");
            ((ObjectNode) export.withArray("issues").get(0).path("triage")).put("comment", "bell\u0007 lone\uD800 ok\uD83D\uDE00");
            Workbook workbook = Fixtures.read(ReportDemo.render(Fixtures.bytes(export)));
            assertThat(column(sheet(workbook, "Issues"), "Triage comment").getFirst())
                    .isEqualTo("bell\uFFFD lone\uFFFD ok\uD83D\uDE00");
        }

        @Test
        @DisplayName("a backlog of identical issues stays under the reader's inflation ratio")
        void repetitive() {
            ObjectNode export = Fixtures.tree("sample.json");
            ArrayNode issues = export.withArray("issues");
            JsonNode template = issues.get(1);
            issues.removeAll();
            for (int i = 0; i < 20_000; i++) {
                issues.add(((ObjectNode) template.deepCopy()).put("id", 10_000 + i));
            }
            Workbook workbook = Fixtures.read(ReportDemo.render(Fixtures.bytes(export)));
            assertThat(sheet(workbook, "Issues").lastRow()).isEqualTo(20_001);
        }
    }

    /** The sample as a later 1.x would write it: a new part, new fields, a new enumeration value. */
    static ObjectNode laterMinor() {
        ObjectNode export = Fixtures.tree("sample.json");
        export.put("schema_version", "1.3");
        export.putObject("posture_hint").put("unknown", true);
        ObjectNode issue = (ObjectNode) export.withArray("issues").get(0);
        issue.put("exploitability", "high");
        issue.put("severity", "catastrophic");
        StreamSupport.stream(export.withArray("checklists").spliterator(), false)
                .forEach(checklist -> ((ObjectNode) checklist).put("archived", false));
        return export;
    }

    private static int rowLabelled(Sheet sheet, String label) {
        for (int row = 1; row <= sheet.lastRow(); row++) {
            if (sheet.text(new CellRef(1, row)).equals(label)) {
                return row;
            }
        }
        throw new AssertionError("no row labelled " + label);
    }

    private static int columnNumber(Sheet sheet, String title) {
        return sheet.row(1).entrySet().stream().filter(cell -> sheet.text(cell.getKey()).equals(title))
                .findFirst().orElseThrow().getKey().column();
    }

    private record Result(int code, String stderr, Path output) {}

    private static Result run(Path directory, byte[] export) throws IOException {
        Path input = Files.write(directory.resolve("export.json"), export);
        Path output = directory.resolve("summary.xlsx");
        Files.deleteIfExists(output);
        return run(new String[] {"--in", input.toString(), "--out", output.toString()});
    }

    private static Result run(String[] args) {
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = ReportDemo.run(args, new PrintStream(err, true, StandardCharsets.UTF_8));
        return new Result(code, err.toString(StandardCharsets.UTF_8),
                args.length == 4 ? Path.of(args[3]) : Path.of("absent"));
    }
}
