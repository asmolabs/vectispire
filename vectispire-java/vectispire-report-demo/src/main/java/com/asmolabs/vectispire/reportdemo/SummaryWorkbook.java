package com.asmolabs.vectispire.reportdemo;

import com.asmolabs.vectispire.reportdemo.Xlsx.Cell;
import com.asmolabs.vectispire.reportdemo.Xlsx.Row;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The three sheets of {@code summary.xlsx} (decision 0035 §6), drawn from the export and from nothing else.
 *
 * <ul>
 *   <li><b>Summary</b> — the project, who asked, the Vectispire version, the export's instant, the gate's
 *       last verdict per target, and the counts per type, severity, state and triage status;
 *   <li><b>Issues</b> — one row per issue the export lists, triage and remediation included;
 *   <li><b>Checklists</b> — one row per line of each embedded checklist, its answer and who gave it.
 * </ul>
 *
 * <p><b>Nothing invented.</b> A value the export leaves null stays an empty cell — never "0", never "none":
 * the schema says null means "not recorded", and a summary that printed a zero for it would state what
 * nobody measured. The one fallback is a person without a display name, named by account id, which is
 * how the export itself names them. The instant on the Summary sheet is the export's, never the moment
 * of rendering: the same export gives the same workbook.
 *
 * <p><b>Order is the export's.</b> Its arrays are already ordered (issues by id, targets repositories then
 * images); re-sorting here would be a second rule for the same order.
 */
final class SummaryWorkbook {

    static final String SUMMARY = "Summary";
    static final String ISSUES = "Issues";
    static final String CHECKLISTS = "Checklists";

    /** The Issues sheet's columns, in order: a test and a reader find a column by its title. */
    static final List<String> ISSUE_COLUMNS = List.of("Id", "Target", "Type", "Severity", "Identifier", "Title",
            "Tool", "Component", "Version", "Path", "Line", "First seen", "Last seen", "State", "KEV", "EPSS", "CVSS",
            "Fix versions", "Triage status", "Justification", "Triage comment", "Decided by", "Decided at",
            "Review at", "Remediation due", "Remediation state");

    static final List<String> CHECKLIST_COLUMNS = List.of("Template", "Revision", "Status", "Signed", "Draft",
            "Package SHA-256", "Line", "Domain", "Control", "Answer", "Answer comment", "Answered by",
            "Answered by kind", "Answered at", "Reconciliation", "Measured", "Evidence");

    static final List<String> COUNT_COLUMNS = List.of("Type", "Severity", "State", "Triage status", "Count");

    static final List<String> GATE_COLUMNS = List.of("Target", "Verdict", "Decided at", "Policy", "Violations",
            "Critical", "High", "Medium", "Low");

    private final ExportDocument export;
    private final Map<String, String> targetNames = new HashMap<>();

    private SummaryWorkbook(ExportDocument export) {
        this.export = export;
        JsonNode project = export.part("project");
        for (JsonNode repository : project.path("repositories")) {
            targetNames.put("repository/" + repository.path("id").asLong(),
                    text(repository.path("name")) == null ? text(repository.path("url")) : text(repository.path("name")));
        }
        for (JsonNode container : project.path("containers")) {
            String image = text(container.path("image"));
            String tag = text(container.path("tag"));
            targetNames.put("container/" + container.path("id").asLong(),
                    image == null ? null : tag == null ? image : image + ":" + tag);
        }
    }

    static byte[] render(ExportDocument export) {
        SummaryWorkbook workbook = new SummaryWorkbook(export);
        return Xlsx.write(List.of(workbook.summary(), workbook.issues(), workbook.checklists()));
    }

    private Xlsx.Sheet summary() {
        JsonNode about = export.part("export");
        JsonNode project = export.part("project");
        List<Row> rows = new ArrayList<>();
        rows.add(Row.heading("Project summary"));
        rows.add(Row.of(Cell.of("Project"), Cell.of(text(project.path("name")))));
        rows.add(Row.of(Cell.of("Project id"), number(project.path("id"))));
        rows.add(Row.of(Cell.of("Solution"), Cell.of(text(project.path("solution").path("name")))));
        rows.add(Row.of(Cell.of("Requested by"), Cell.of(person(about.path("requester")))));
        rows.add(Row.of(Cell.of("Installation"), Cell.of(text(about.path("installation").path("name")))));
        rows.add(Row.of(Cell.of("Vectispire version"), Cell.of(text(about.path("product_version")))));
        rows.add(Row.of(Cell.of("Exported at"), Cell.of(text(about.path("generated_at")))));
        rows.add(Row.of(Cell.of("Export"), Cell.of(text(about.path("id")))));
        rows.add(Row.of(Cell.of("Export schema"), Cell.of(ExportDocument.SCHEMA + " "
                + export.root().path("schema_version").asText())));
        rows.add(Row.of(Cell.of("Issues listed"), Cell.of(export.part("issues").size())));

        rows.add(Row.blank());
        rows.add(Row.heading("Gate, last verdict per target"));
        rows.add(Row.heading(GATE_COLUMNS.toArray(String[]::new)));
        for (JsonNode entry : export.part("gate")) {
            JsonNode verdict = entry.path("verdict");
            if (!verdict.isObject()) {
                rows.add(Row.of(Cell.of(target(entry.path("target"))), Cell.of("never judged")));
                continue;
            }
            String policy = text(verdict.path("policy_source"));
            JsonNode version = verdict.path("policy_version");
            rows.add(Row.of(Cell.of(target(entry.path("target"))),
                    Cell.of(verdict.path("passed").asBoolean() ? "passed" : "failed"),
                    Cell.of(text(verdict.path("decided_at"))),
                    Cell.of(policy == null ? null : version.isIntegralNumber() ? policy + " v" + version.asLong() : policy),
                    number(verdict.path("violations")), number(verdict.path("critical")), number(verdict.path("high")),
                    number(verdict.path("medium")), number(verdict.path("low"))));
        }

        rows.add(Row.blank());
        rows.add(Row.heading("Issues by type and severity"));
        rows.add(Row.heading(COUNT_COLUMNS.toArray(String[]::new)));
        long total = 0;
        for (JsonNode count : export.part("issue_counts")) {
            rows.add(Row.of(Cell.of(text(count.path("type"))), Cell.of(text(count.path("severity"))),
                    Cell.of(text(count.path("state"))), Cell.of(text(count.path("triage_status"))),
                    number(count.path("count"))));
            total += count.path("count").asLong();
        }
        rows.add(new Row(List.of(Cell.of("Total"), Cell.EMPTY, Cell.EMPTY, Cell.EMPTY, Cell.of(total)), true));
        return new Xlsx.Sheet(SUMMARY, List.of(28, 22, 22, 22, 12, 10, 10, 10, 10), rows);
    }

    private Xlsx.Sheet issues() {
        List<Row> rows = new ArrayList<>();
        rows.add(Row.heading(ISSUE_COLUMNS.toArray(String[]::new)));
        for (JsonNode issue : export.part("issues")) {
            JsonNode component = issue.path("component");
            JsonNode triage = issue.path("triage");
            JsonNode remediation = issue.path("remediation");
            rows.add(Row.of(
                    number(issue.path("id")),
                    Cell.of(target(issue.path("target"))),
                    Cell.of(text(issue.path("type"))),
                    Cell.of(text(issue.path("severity"))),
                    Cell.of(text(issue.path("identifier"))),
                    Cell.of(text(issue.path("title"))),
                    Cell.of(text(issue.path("tool"))),
                    Cell.of(text(component.path("name"))),
                    Cell.of(text(component.path("version"))),
                    Cell.of(text(issue.path("path"))),
                    number(issue.path("line")),
                    Cell.of(text(issue.path("first_seen_at"))),
                    Cell.of(text(issue.path("last_seen_at"))),
                    Cell.of(text(issue.path("state"))),
                    issue.path("kev").isBoolean() ? Cell.of(issue.path("kev").asBoolean() ? "yes" : "no") : Cell.EMPTY,
                    decimal(issue.path("epss")),
                    decimal(issue.path("cvss")),
                    Cell.of(text(issue.path("fix_versions"))),
                    Cell.of(text(triage.path("status"))),
                    Cell.of(text(triage.path("justification"))),
                    Cell.of(text(triage.path("comment"))),
                    Cell.of(triage.path("decided_by").isObject() ? person(triage.path("decided_by")) : null),
                    Cell.of(text(triage.path("decided_at"))),
                    Cell.of(text(triage.path("review_at"))),
                    Cell.of(text(remediation.path("due_at"))),
                    Cell.of(text(remediation.path("state")))));
        }
        List<Integer> widths = new ArrayList<>();
        for (String column : ISSUE_COLUMNS) {
            widths.add(column.equals("Title") || column.equals("Triage comment") ? 50 : 16);
        }
        return new Xlsx.Sheet(ISSUES, widths, rows);
    }

    private Xlsx.Sheet checklists() {
        List<Row> rows = new ArrayList<>();
        rows.add(Row.heading(CHECKLIST_COLUMNS.toArray(String[]::new)));
        for (JsonNode checklist : export.part("checklists")) {
            JsonNode statement = checklist.path("statement");
            JsonNode template = statement.path("template");
            String templateName = text(template.path("name"));
            Cell templateCell = Cell.of(templateName == null ? text(template.path("slug")) : templateName);
            for (JsonNode line : statement.path("lines")) {
                JsonNode answer = line.path("answer");
                JsonNode measurement = line.path("measurement");
                rows.add(Row.of(
                        templateCell,
                        number(statement.path("revision")),
                        Cell.of(text(statement.path("status"))),
                        Cell.of(statement.path("signed").asBoolean() ? "yes" : "no"),
                        Cell.of(checklist.path("draft").asBoolean() ? "yes" : "no"),
                        Cell.of(text(checklist.path("document_sha256"))),
                        Cell.of(text(line.path("key"))),
                        Cell.of(text(line.path("domain"))),
                        Cell.of(text(line.path("control"))),
                        Cell.of(answer.isObject() ? first(text(answer.path("word")), text(answer.path("value"))) : null),
                        Cell.of(text(answer.path("comment"))),
                        Cell.of(text(answer.path("answeredBy"))),
                        Cell.of(text(answer.path("answeredByKind"))),
                        Cell.of(text(answer.path("answeredAt"))),
                        Cell.of(text(line.path("reconciliation"))),
                        Cell.of(measurement.isObject() ? first(text(measurement.path("summary")),
                                text(measurement.path("outcome"))) : null),
                        evidence(line.path("evidence"))));
            }
        }
        return new Xlsx.Sheet(CHECKLISTS, List.of(24, 9, 12, 8, 8, 20, 12, 20, 50, 14, 40, 20, 12, 22, 16, 40, 30),
                rows);
    }

    /** The proofs still standing, named by file name or link — a report cites a file, never carries it. */
    private static Cell evidence(JsonNode proofs) {
        List<String> named = new ArrayList<>();
        for (JsonNode proof : proofs) {
            if (text(proof.path("withdrawnAt")) != null) {
                continue;
            }
            String name = first(text(proof.path("fileName")), text(proof.path("link")));
            String sha256 = text(proof.path("sha256"));
            if (name != null) {
                named.add(sha256 == null ? name : name + " (sha256 " + sha256 + ")");
            }
        }
        return named.isEmpty() ? Cell.EMPTY : Cell.of(String.join("\n", named));
    }

    private String target(JsonNode target) {
        String kind = text(target.path("kind"));
        if (kind == null) {
            return null;
        }
        long id = target.path("id").asLong();
        String name = targetNames.get(kind + "/" + id);
        return name == null ? kind + " #" + id : kind + " " + name;
    }

    /** A person as the export names them: by display name, else by account, else not at all. */
    private static String person(JsonNode person) {
        String name = text(person.path("display_name"));
        if (name != null) {
            return name;
        }
        JsonNode account = person.path("account_id");
        return account.isIntegralNumber() ? "account " + account.asLong() : null;
    }

    private static String first(String preferred, String fallback) {
        return preferred != null ? preferred : fallback;
    }

    /** The node's text, or null where it is absent or null — never the string "null". */
    private static String text(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() ? null
                : node.isValueNode() ? node.asText() : node.toString();
    }

    private static Cell number(JsonNode node) {
        return node.isIntegralNumber() ? Cell.of(node.asLong()) : Cell.of(text(node));
    }

    private static Cell decimal(JsonNode node) {
        return node.isNumber() ? new Cell.Decimal(node.asDouble()) : Cell.of(text(node));
    }
}
