package com.asmolabs.vectispire.core.checklists.internal;

import com.asmolabs.vectispire.common.domain.checklists.AnswerWords;
import com.asmolabs.vectispire.common.domain.checklists.CellRef;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistColumn;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistLayout;
import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule;
import com.asmolabs.vectispire.common.domain.checklists.HeaderCell;
import com.asmolabs.vectispire.common.domain.checklists.ItemKey;
import com.asmolabs.vectispire.common.domain.checklists.VersionPairing;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.core.checklists.ChecklistRuleForm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * The JSON a template version's row keeps — its confirmed layout, its pairs made by hand, the
 * accounts that wrote the draft — in forms of their own; and a line's bound rule between the API's
 * shape and the domain's canonical form, which is what the item stores.
 *
 * <p><b>Not the API's records.</b> The layout stored here is what the renderer will read to write
 * answers into the organisation's workbook (decision 0032 §3: "the renderer reads nothing else"),
 * next year as well as today. Serialising the route's request record would make every change to
 * the route a change to what stored rows mean; a form of its own, tagged with its version, changes
 * only on purpose. A row that does not read back is a defect, not the caller's input, and says so.
 */
@Component
public class StoredForms {

    /** Written into every stored layout; a new shape is a new number, and the old one still reads. */
    static final int LAYOUT_FORM = 1;

    private final ObjectMapper json;

    public StoredForms(ObjectMapper json) {
        this.json = json;
    }

    /** Somebody who wrote a draft: the account, and the name it had when it did. */
    public record DraftAuthor(long accountId, String username) {}

    record StoredCell(String label, String value) {}

    record StoredLayout(
            int form,
            String sheet,
            Map<String, String> columns,
            int firstItemRow,
            int lastItemRow,
            Map<String, StoredCell> header,
            String yes,
            String no,
            String notApplicable) {}

    record StoredPair(String added, String removed) {}

    public String layout(ChecklistLayout layout) {
        Map<String, String> columns = new LinkedHashMap<>();
        layout.columns().forEach((column, letters) -> columns.put(column.wireName(), letters));
        Map<String, StoredCell> header = new LinkedHashMap<>();
        layout.header().forEach((field, cell) ->
                header.put(field.wireName(), new StoredCell(cell.label().toString(), cell.value().toString())));
        return write(new StoredLayout(LAYOUT_FORM, layout.sheet(), columns, layout.firstItemRow(), layout.lastItemRow(),
                header, layout.answers().yes(), layout.answers().no(), layout.answers().notApplicable().orElse(null)));
    }

    public ChecklistLayout layout(String stored) {
        StoredLayout form = read(stored, new TypeReference<>() {});
        if (form.form() != LAYOUT_FORM) {
            throw new IllegalStateException("A stored layout is in form " + form.form() + ", which this version cannot read.");
        }
        Map<ChecklistColumn, String> columns = new EnumMap<>(ChecklistColumn.class);
        form.columns().forEach((name, letters) ->
                columns.put(ChecklistColumn.valueOf(name.toUpperCase(Locale.ROOT)), letters));
        Map<HeaderCell.Field, HeaderCell> header = new EnumMap<>(HeaderCell.Field.class);
        form.header().forEach((name, cell) -> header.put(HeaderCell.Field.valueOf(name.toUpperCase(Locale.ROOT)),
                new HeaderCell(stored(cell.label()), stored(cell.value()))));
        return new ChecklistLayout(form.sheet(), columns, form.firstItemRow(), form.lastItemRow(), header,
                new AnswerWords(form.yes(), form.no(), Optional.ofNullable(form.notApplicable())));
    }

    /** Null for none, which is how a draft without pairs stores them. */
    public String pairs(List<VersionPairing.ManualPair> pairs) {
        if (pairs.isEmpty()) {
            return null;
        }
        return write(pairs.stream().map(pair -> new StoredPair(pair.added().value(), pair.removed().value())).toList());
    }

    public List<VersionPairing.ManualPair> pairs(String stored) {
        if (stored == null) {
            return List.of();
        }
        List<StoredPair> pairs = read(stored, new TypeReference<>() {});
        return pairs.stream()
                .map(pair -> new VersionPairing.ManualPair(new ItemKey(pair.added()), new ItemKey(pair.removed())))
                .toList();
    }

    public String authors(List<DraftAuthor> authors) {
        return write(authors);
    }

    public List<DraftAuthor> authors(String stored) {
        return read(stored, new TypeReference<>() {});
    }

    /**
     * A rule as a request states it, read by the domain, which alone decides what a rule is: the API's
     * record is turned into its JSON and parsed like any other statement of one, refused in words.
     */
    public ChecklistRule rule(ChecklistRuleForm form) {
        if (form == null) {
            throw new InvalidInputException("A rule is an object: its kind, its maximum age and its parameters.");
        }
        return ChecklistRule.parse(json.<JsonNode>valueToTree(form));
    }

    /**
     * A stored rule — the domain's canonical form, which is what the item keeps and its digest reads —
     * in the API's shape. Never the other way round: the stored form is not the route's record.
     */
    public ChecklistRuleForm ruleForm(String canonical) {
        return read(canonical, new TypeReference<>() {});
    }

    private static CellRef stored(String reference) {
        return CellRef.parse(reference)
                .orElseThrow(() -> new IllegalStateException("A stored layout names the cell \"" + reference + "\"."));
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException unwritable) {
            throw new IllegalStateException("A template version's form could not be written.", unwritable);
        }
    }

    private <T> T read(String stored, TypeReference<T> type) {
        try {
            return json.readValue(stored, type);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("A template version's stored form is unreadable.", unreadable);
        }
    }
}
