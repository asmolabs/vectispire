package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * What the checklist workbook answers for {@code checklists/workbooks.json} — the answers the Rust port's stage 1b
 * ({@code vectispire_cp_checklists}: the reader, the layout and its proposal, the template version, the renderer
 * and {@code DocumentZip}, the statement) is held to.
 *
 * <p>The renderer's bytes are a contract: a document is compared with a second rendering byte for byte (decision
 * 0032 §10), so the Rust renderer writes the same package Java writes, entry for entry, deflated alike. The reader's
 * answers are every refusal's sentence — the zip's guards, the XML, the cells — and, for a workbook it reads, every
 * cell, merge, validation and defined name, and the layout proposed from it. {@code checklist.json} is written by the
 * control plane's mapper, configured here as {@code CoreConfiguration} configures it.
 *
 * <p>An answer is the value, {@code {"refused": message}} for an {@link InvalidInputException}, {@code {"illegal":
 * message}} for the {@link IllegalArgumentException} or {@link IllegalStateException} a defect raises, and {@code
 * {"writtenFormula": …}} for a {@link WrittenFormulaException}, with its cells.
 */
class WorkbookReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final ObjectMapper PLAIN = new ObjectMapper();
    /** {@code CoreConfiguration.objectMapper()}: what writes {@code checklist.json}. */
    private static final ObjectMapper DOCUMENT = JsonMapper.builder()
            .addModule(new JavaTimeModule())
            .addModule(new Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();
    private static final long TEN_MB = 10L * 1024 * 1024;

    @Test
    void theAnswersTheRustWorkbookIsHeldTo() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("checklists/workbooks.json"));
        ObjectNode answers = JSON.createObjectNode();

        List<byte[]> files = new java.util.ArrayList<>();
        ArrayNode workbooks = answers.putArray("workbooks");
        for (JsonNode input : inputs.path("workbooks")) {
            byte[] file = Base64.getDecoder().decode(input.path("xlsx").asText());
            files.add(file);
            workbooks.add(answer(() -> {
                Workbook workbook = Workbook.read(file, input.path("maxBytes").isNumber() ? input.path("maxBytes").asLong()
                        : TEN_MB, limits(input.path("limits")));
                ObjectNode node = workbook(workbook);
                node.set("proposal", answer(() -> proposal(LayoutProposal.of(workbook))));
                return node;
            }));
        }

        ArrayNode layouts = answers.putArray("layouts");
        inputs.path("layouts").forEach(input -> layouts.add(answer(() -> layout(layout(input)))));

        ArrayNode versions = answers.putArray("versions");
        for (JsonNode input : inputs.path("versions")) {
            versions.add(answer(() -> {
                Workbook workbook = Workbook.read(files.get(input.path("workbook").asInt()), TEN_MB);
                ArrayNode items = PLAIN.createArrayNode();
                TemplateVersion.read(workbook, layout(input.path("layout"))).items().forEach(item -> items.addObject()
                        .put("key", item.key().value()).put("position", item.position()).put("domain", item.domain())
                        .put("objective", item.objective()).put("control", item.control())
                        .put("contact", item.contact()).put("kpi", item.kpi()).put("row", item.row())
                        .put("contentDigest", item.contentDigest()));
                return items;
            }));
        }

        ArrayNode renders = answers.putArray("renders");
        for (JsonNode input : inputs.path("renders")) {
            byte[] template = files.get(input.path("workbook").asInt());
            renders.add(answer(() -> rendered(ChecklistRenderer.render(template, layout(input.path("layout")),
                    statement(input.path("statement"))))));
        }

        ArrayNode trials = answers.putArray("trials");
        for (JsonNode input : inputs.path("trials")) {
            byte[] template = files.get(input.path("workbook").asInt());
            trials.add(answer(() -> {
                ChecklistLayout layout = layout(input.path("layout"));
                List<ChecklistItem> items = TemplateVersion.read(Workbook.read(template, TEN_MB), layout).items();
                return rendered(ChecklistRenderer.trial(template, layout, items));
            }));
        }

        ArrayNode statements = answers.putArray("statements");
        for (JsonNode input : inputs.path("statements")) {
            statements.add(answer(() -> {
                ChecklistStatement statement = statement(input);
                return PLAIN.createObjectNode()
                        .put("json", text(statement))
                        .put("renamed", text(statement.withNames(name -> "<" + name + ">")));
            }));
        }

        ArrayNode serials = answers.putArray("serials");
        inputs.path("serials").forEach(input -> serials.add(ChecklistRenderer.serial(
                Instant.parse(input.path("instant").asText()), input.path("date1904").asBoolean())));

        ArrayNode zips = answers.putArray("zips");
        for (JsonNode input : inputs.path("zips")) {
            LinkedHashMap<String, DocumentZip.Entry> entries = new LinkedHashMap<>();
            input.forEach(entry -> entries.put(entry.path("name").asText(), new DocumentZip.Entry(
                    Base64.getDecoder().decode(entry.path("bytes").asText()), entry.path("stored").asBoolean(),
                    entry.path("directory").asBoolean())));
            zips.add(Base64.getEncoder().encodeToString(DocumentZip.of(entries)));
        }

        ReferenceSet.expect("checklists/workbooks-java-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    // ------------------------------------------------------------------ the inputs

    private static Workbook.Limits limits(JsonNode node) {
        if (!node.isObject()) {
            return Workbook.Limits.DEFAULT;
        }
        return new Workbook.Limits(node.path("maxEntries").asInt(), node.path("maxEntryBytes").asLong(),
                node.path("maxInflatedBytes").asLong(), node.path("maxRatio").asInt(),
                node.path("ratioGraceBytes").asLong(), node.path("maxElements").asLong(), node.path("maxSheets").asInt(),
                node.path("maxCells").asInt(), node.path("maxSharedStrings").asInt());
    }

    /** Built as a caller builds it: the columns in the order given, the header cells, the words, then the layout. */
    private static ChecklistLayout layout(JsonNode input) {
        Map<ChecklistColumn, String> columns = new LinkedHashMap<>();
        input.path("columns").forEach(pair -> columns.put(
                ChecklistColumn.valueOf(pair.get(0).asText().toUpperCase(Locale.ROOT)), text(pair.get(1))));
        Map<HeaderCell.Field, HeaderCell> header = new LinkedHashMap<>();
        input.path("header").forEach(cell -> header.put(
                HeaderCell.Field.valueOf(cell.get(0).asText().toUpperCase(Locale.ROOT)),
                new HeaderCell(CellRef.parse(cell.get(1).asText()).orElseThrow(),
                        CellRef.parse(cell.get(2).asText()).orElseThrow())));
        JsonNode words = input.path("answers");
        AnswerWords answers = new AnswerWords(text(words.get(0)), text(words.get(1)), Optional.ofNullable(text(words.get(2))));
        return new ChecklistLayout(text(input.path("sheet")), columns, input.path("firstItemRow").asInt(),
                input.path("lastItemRow").asInt(), header, answers);
    }

    private static ChecklistStatement statement(JsonNode input) {
        try {
            return DOCUMENT.treeToValue(input, ChecklistStatement.class);
        } catch (JsonMappingException unreadable) {
            if (unreadable.getCause() instanceof RuntimeException defect) {
                throw defect;
            }
            throw new IllegalStateException(unreadable.getOriginalMessage());
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable.getMessage());
        }
    }

    // ------------------------------------------------------------------ the answers' shapes

    private static JsonNode answer(Supplier<JsonNode> computed) {
        try {
            return computed.get();
        } catch (WrittenFormulaException refused) {
            ObjectNode node = PLAIN.createObjectNode();
            ObjectNode written = node.putObject("writtenFormula").put("message", refused.getMessage());
            ArrayNode cells = written.putArray("cells");
            refused.cells().forEach(cell -> cells.addArray().add(cell.cell()).add(cell.kind()).add(cell.range()));
            return node;
        } catch (InvalidInputException refused) {
            return PLAIN.createObjectNode().put("refused", refused.getMessage());
        } catch (IllegalArgumentException | IllegalStateException defect) {
            return PLAIN.createObjectNode().put("illegal", defect.getMessage());
        }
    }

    private static String text(JsonNode node) {
        return node == null || node.isNull() || node.isMissingNode() ? null : node.asText();
    }

    private static String text(ChecklistStatement statement) {
        try {
            return new String(DOCUMENT.writerWithDefaultPrettyPrinter().writeValueAsBytes(statement), StandardCharsets.UTF_8);
        } catch (Exception unwritable) {
            throw new IllegalStateException(unwritable);
        }
    }

    private static ObjectNode rendered(byte[] bytes) {
        return PLAIN.createObjectNode().put("sha256", Digests.sha256Hex(bytes))
                .put("bytes", Base64.getEncoder().encodeToString(bytes));
    }

    private static ObjectNode workbook(Workbook workbook) {
        ObjectNode node = PLAIN.createObjectNode().put("sha256", workbook.sha256());
        ArrayNode sheets = node.putArray("sheets");
        for (Sheet sheet : workbook.sheets()) {
            ObjectNode written = sheets.addObject().put("name", sheet.name()).put("lastRow", sheet.lastRow());
            ArrayNode cells = written.putArray("cells");
            sheet.cells().forEach((cell, value) -> {
                ArrayNode entry = cells.addArray().add(cell.toString());
                switch (value) {
                    case CellValue.Text text -> entry.add("text").add(text.text());
                    case CellValue.Number number -> entry.add("number").add(number.literal());
                    case CellValue.Bool bool -> entry.add("bool").add(bool.value());
                    case CellValue.Error error -> entry.add("error").add(error.code());
                    case CellValue.Formula formula -> entry.add("formula").add(formula.expression())
                            .add(formula.cached().orElse(null));
                }
            });
            ArrayNode merged = written.putArray("merged");
            sheet.merged().forEach(range -> merged.add(range.toString()));
            ArrayNode validations = written.putArray("validations");
            for (ListValidation validation : sheet.validations()) {
                ObjectNode list = validations.addObject();
                ArrayNode ranges = list.putArray("ranges");
                validation.ranges().forEach(range -> ranges.add(range.toString()));
                list.put("source", validation.source()).put("fromExtension", validation.fromExtension())
                        .put("singleColumn", validation.singleColumn()).put("cellCount", validation.cellCount());
                ArrayNode values = list.putArray("values");
                workbook.listValues(validation, sheet).forEach(values::add);
            }
        }
        ArrayNode names = node.putArray("definedNames");
        workbook.definedNames().forEach((name, formula) -> names.addArray().add(name).add(formula));
        return node;
    }

    private static ObjectNode proposal(LayoutProposal proposal) {
        ObjectNode node = PLAIN.createObjectNode().put("sheet", proposal.sheet())
                .put("columnHeaderRow", proposal.columnHeaderRow().orElse(null))
                .put("firstItemRow", proposal.firstItemRow().orElse(null))
                .put("lastItemRow", proposal.lastItemRow().orElse(null));
        ObjectNode columns = node.putObject("columns");
        proposal.columns().forEach((column, letters) -> columns.put(column.wireName(), letters));
        ObjectNode header = node.putObject("header");
        proposal.header().forEach((field, cell) -> header.putArray(field.wireName()).add(cell.label().toString())
                .add(cell.value().toString()));
        ArrayNode values = node.putArray("answerValues");
        proposal.answerValues().forEach(values::add);
        return node;
    }

    private static ObjectNode layout(ChecklistLayout layout) {
        ObjectNode node = PLAIN.createObjectNode().put("sheet", layout.sheet());
        ObjectNode columns = node.putObject("columns");
        layout.columns().forEach((column, letters) -> columns.put(column.wireName(), letters));
        ObjectNode indexes = node.putObject("indexes");
        for (ChecklistColumn column : ChecklistColumn.values()) {
            layout.column(column).ifPresent(index -> indexes.put(column.wireName(), index));
        }
        node.put("firstItemRow", layout.firstItemRow()).put("lastItemRow", layout.lastItemRow());
        ObjectNode header = node.putObject("header");
        layout.header().forEach((field, cell) -> header.putArray(field.wireName()).add(cell.label().toString())
                .add(cell.value().toString()));
        return node.put("offersNotApplicable", layout.offersNotApplicable());
    }
}
