package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.asmolabs.vectispire.core.issues.BacklogEntry;
import com.asmolabs.vectispire.core.issues.IssueQueryService;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.issues.TriageHistory;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.plugins.PluginActivationView;
import com.asmolabs.vectispire.core.plugins.persistence.PluginActivationEntity;
import com.asmolabs.vectispire.core.reportplugins.ReportPluginActivationView;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginActivationEntity;
import com.asmolabs.vectispire.core.services.EntityViewsTest;
import com.asmolabs.vectispire.core.threatintel.web.EpssFleetSummaryView;
import com.asmolabs.vectispire.core.settings.IntegrationView;
import com.asmolabs.vectispire.core.settings.persistence.IntegrationEntity;
import com.asmolabs.vectispire.core.tickets.IssueTicketView;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTicketEntity;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Table;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.provider.Arguments;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The served document says which fields of a response may be null, and says it truly.
 *
 * <h2>Why</h2>
 *
 * <p><b>The document said {@code string} of every reference field</b>, and the generated client
 * turned that into {@code link?: string}: a value, or no key at all. The server sends neither — the
 * key, holding {@code null} — on every secret, every SAST finding, every untriaged issue. A screen
 * typed against the document believed it, and the one that did not had to say so by hand, field by
 * field, in {@code api.models.ts}. A field declared nullable that the server never nulls is the same
 * lie the other way round: it makes every reader guard a case that cannot happen.
 *
 * <h2>The rule, and where it can be read</h2>
 *
 * <p><b>A component copied from a column may be null exactly when the column may</b> — read from the
 * running schema, not from {@code @Column}, which Hibernate's validation does not compare on
 * nullability. Two kinds of exception, each stated with its reason below, so that adding one is a
 * decision: a column that allows null and that every producer fills ({@link Audited#filled}), and a
 * component no column holds ({@link Audited#derived}), whose nullability is read from the code that
 * builds it. A component the audit neither finds a column for nor states fails, so a new one is
 * decided rather than inherited.
 *
 * <p><b>Every view {@link EntityViewsTest} pairs with an entity is audited or listed as not yet
 * audited</b>, and that list only shrinks: a view on it whose document already agrees with its
 * columns fails, asking to be moved. The records that copy no entity — the backlog's row, an issue's
 * sightings — have no column to read; they are audited by statement only, which is a list of
 * decisions rather than a proof, and pins them against a component added without one.
 */
@DisplayName("which response fields the document says may be null")
class ResponseNullabilityTest extends ApiTestBase {

    /**
     * A response record, the entity whose like-named columns it copies (or none), and what the
     * columns cannot say.
     *
     * @param filled components whose column allows null and that every producer fills, with the reason
     * @param derived components no column holds, and whether the server may send them as null
     */
    record Audited(
            Class<? extends Record> view,
            Class<?> entity,
            Map<String, String> filled,
            Map<String, Boolean> derived) {}

    private static final Map<String, String> ISSUE_FILLED = Map.of(
            "identifier", "every producer names one: the scanners fall back to \"unknown\", a SARIF result "
                    + "without a rule is refused, a licence or an end of life is its own identifier",
            "source", "the scanner's name, the plugin's id or the SARIF driver's name, which the import requires",
            "severity", "every producer grades the finding; one without a grade reads medium or unknown");

    private static final List<Audited> AUDITED = List.of(
            new Audited(IssueView.class, IssueEntity.class, ISSUE_FILLED, Map.of()),
            new Audited(IssueTicketView.class, IssueTicketEntity.class, Map.of(), Map.of()),
            // The registry's entries: the family and the name come from the catalogue, never null; who switched
            // it and when are null until the governor first does, and the author is withheld from a reader the
            // governance trail is not shown to (decision 0040).
            new Audited(IntegrationView.class, IntegrationEntity.class, Map.of(),
                    Map.of("family", false, "name", false)),
            // The project's labels, and the plugin's name, are null only when a deletion races the read.
            new Audited(PluginActivationView.class, PluginActivationEntity.class, Map.of(),
                    Map.of("projectName", true, "solutionId", true, "solutionName", true)),
            new Audited(ReportPluginActivationView.class, ReportPluginActivationEntity.class, Map.of(),
                    Map.of("pluginName", true)),
            new Audited(TriageHistory.ObservedIssue.class, IssueEntity.class,
                    Map.of("identifier", ISSUE_FILLED.get("identifier"), "severity", ISSUE_FILLED.get("severity")),
                    Map.of("decisions", false)),
            new Audited(TriageHistory.Decision.class, TriageEventEntity.class, Map.of(),
                    // The scan's version: null when it read none, and always on an issue's detail.
                    Map.of("version", true)),
            new Audited(BacklogEntry.class, null, Map.of(), Map.of(
                    "targetKind", false,
                    // TargetNaming.DELETED when the target went meanwhile.
                    "targetName", false,
                    // All three null when no remediation window applies.
                    "slaDueAt", true,
                    "slaState", true,
                    "slaDays", true)),
            new Audited(IssueQueryService.IssueDetail.class, null, Map.of(), Map.of(
                    "targetKind", false,
                    "targetName", false,
                    "sightings", false,
                    "decisions", false)),
            new Audited(IssueQueryService.Sighting.class, null, Map.of(), Map.of(
                    // t_scan.id, status, branch and created_at are not null; the finding's severity is
                    // filled by every producer, as the issue's is.
                    "scanId", false,
                    "status", false,
                    "branch", false,
                    "version", true,
                    "scannedAt", false,
                    "severity", false)),
            // A row of the EPSS ranking: only the scores nobody measured are null
            // (EpssPrioritizationService, "unknown stays unknown").
            new Audited(EpssFleetSummaryView.EpssPrioritizedIssueView.class, null, Map.of(), Map.ofEntries(
                    Map.entry("issueId", false),
                    Map.entry("identifier", false),
                    Map.entry("title", false),
                    Map.entry("severity", false),
                    Map.entry("cvssScore", true),
                    Map.entry("epssScore", true),
                    Map.entry("epssPercentile", true),
                    Map.entry("targetName", false),
                    Map.entry("targetKind", false),
                    Map.entry("priorityTier", false),
                    Map.entry("recommendedAction", false))));

    /**
     * The entity views whose nullability nobody has audited yet. **This list only shrinks**: a view
     * whose document already agrees with its columns fails below until it moves to {@link #AUDITED}.
     */
    private static final Set<String> NOT_YET_AUDITED = Set.of(
            "AuditEntryView",
            "ApiContractView",
            "SolutionView",
            "ProjectView",
            "ReportRunView",
            "ForgeDiscoveryView",
            "ForgeRepositoryView",
            "SarifSourceView",
            "SarifImportView",
            "CoverageImportView",
            "TestReportImportView",
            "BuildSbomView",
            "ChecklistItemView",
            "ChecklistMeasurementView");

    @Autowired
    private JdbcTemplate jdbc;

    private JsonNode schemas;

    @BeforeEach
    void readTheDocument() throws Exception {
        schemas = json.readTree(mvc.perform(authenticated(get("/v3/api-docs"), asReader()))
                        .andReturn()
                        .getResponse()
                        .getContentAsString())
                .path("components")
                .path("schemas");
    }

    @Test
    @DisplayName("declares null exactly where the column, or the statement, allows it")
    void nullable_where_the_server_sends_null() {
        Map<String, String> disagreements = new TreeMap<>();
        for (Audited audited : AUDITED) {
            JsonNode properties = propertiesOf(audited.view());
            Map<String, Boolean> columns = audited.entity() == null ? Map.of() : columnsOf(audited.entity());

            for (RecordComponent component : audited.view().getRecordComponents()) {
                String name = component.getName();
                String where = schemaName(audited.view()) + "." + name;
                if (unwrapped(audited.view(), component)) {
                    continue; // its record is audited on its own; its properties are compared below
                }
                boolean expected;
                if (component.getType().isPrimitive()) {
                    expected = false;
                } else if (audited.derived().containsKey(name)) {
                    expected = audited.derived().get(name);
                } else if (columns.containsKey(name)) {
                    expected = columns.get(name) && !audited.filled().containsKey(name);
                } else {
                    disagreements.put(where, "has no column on " + simpleName(audited.entity())
                            + " and no statement in this test: say whether the server may send it as null");
                    continue;
                }
                assertThat(properties.has(name)).as("%s is in the document", where).isTrue();
                boolean declared = nullable(properties.get(name));
                if (declared != expected) {
                    disagreements.put(where, expected
                            ? "may be null, and the document does not say so"
                            : "is never null, and the document says it may be");
                }
            }
            for (String filled : audited.filled().keySet()) {
                if (!Boolean.TRUE.equals(columns.get(filled))) {
                    disagreements.put(schemaName(audited.view()) + "." + filled,
                            "is listed as filled although its column does not allow null: remove the line");
                }
            }
        }
        assertThat(disagreements).as("the served document against the schema and the statements").isEmpty();
    }

    @Test
    @DisplayName("says the same of an issue's fields wherever the issue is unwrapped")
    void unwrapped_records_keep_their_nullability() {
        JsonNode issue = propertiesOf(IssueView.class);
        for (Class<? extends Record> carrier : List.of(BacklogEntry.class, IssueQueryService.IssueDetail.class)) {
            JsonNode carried = propertiesOf(carrier);
            issue.fieldNames().forEachRemaining(name -> assertThat(nullable(carried.path(name)))
                    .as("%s.%s", schemaName(carrier), name)
                    .isEqualTo(nullable(issue.get(name))));
        }
    }

    @Test
    @DisplayName("audits every entity view, or lists it as not yet audited, and the list only shrinks")
    void every_entity_view_is_audited_or_listed() {
        Set<Class<?>> audited = new java.util.HashSet<>();
        AUDITED.forEach(entry -> audited.add(entry.view()));
        List<String> problems = new ArrayList<>();

        for (Arguments pair : EntityViewsTest.pairs().toList()) {
            Class<?> entity = (Class<?>) pair.get()[0];
            @SuppressWarnings("unchecked")
            Class<? extends Record> view = (Class<? extends Record>) pair.get()[1];
            if (audited.contains(view)) {
                continue;
            }
            String name = schemaName(view);
            if (!schemas.has(name)) {
                // No route returns it: the document says nothing of it that could be wrong.
                if (NOT_YET_AUDITED.contains(name)) {
                    problems.add(name + " is in no response: remove it from NOT_YET_AUDITED");
                }
                continue;
            }
            if (!NOT_YET_AUDITED.contains(name)) {
                problems.add(name + " is neither audited nor listed as not yet audited");
                continue;
            }
            Map<String, Boolean> columns = columnsOf(entity);
            JsonNode properties = propertiesOf(view);
            boolean disagrees = false;
            for (RecordComponent component : view.getRecordComponents()) {
                Boolean column = columns.get(component.getName());
                if (column != null && !component.getType().isPrimitive()
                        && column != nullable(properties.path(component.getName()))) {
                    disagrees = true;
                }
            }
            if (!disagrees) {
                problems.add(name + " agrees with its columns: audit its derived components and move it to AUDITED");
            }
        }
        assertThat(problems).isEmpty();
    }

    /**
     * {@code @JsonUnwrapped} does not target a record component, so javac copies it onto the field and
     * the accessor and the component itself reports nothing — the trap {@code PrimitivePropertiesAreRequired}
     * describes for {@code @JsonProperty}.
     */
    private static boolean unwrapped(Class<?> record, RecordComponent component) {
        if (component.getAccessor().isAnnotationPresent(JsonUnwrapped.class)) {
            return true;
        }
        try {
            return record.getDeclaredField(component.getName()).isAnnotationPresent(JsonUnwrapped.class);
        } catch (NoSuchFieldException noBackingField) {
            return false;
        }
    }

    private JsonNode propertiesOf(Class<?> record) {
        JsonNode schema = schemas.path(schemaName(record));
        assertThat(schema.isMissingNode()).as("%s is a schema of the document", schemaName(record)).isFalse();
        return schema.path("properties");
    }

    /** OpenAPI 3.1 spells a nullable property as a type list holding "null". */
    private static boolean nullable(JsonNode property) {
        JsonNode type = property.path("type");
        if (type.isArray()) {
            for (JsonNode one : type) {
                if ("null".equals(one.asText())) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Each property of the entity, by its Java name, and whether the running schema lets its column be null. */
    private Map<String, Boolean> columnsOf(Class<?> entity) {
        String table = entity.getAnnotation(Table.class).name();
        Map<String, Boolean> byColumn = new HashMap<>();
        jdbc.query(
                "select column_name, is_nullable from information_schema.columns "
                        + "where table_schema = database() and table_name = ?",
                row -> {
                    byColumn.put(row.getString(1).toLowerCase(java.util.Locale.ROOT), "YES".equals(row.getString(2)));
                },
                table);
        assertThat(byColumn).as("the columns of %s", table).isNotEmpty();

        Map<String, Boolean> byProperty = new HashMap<>();
        for (Class<?> type = entity; type != null && type != Object.class; type = type.getSuperclass()) {
            for (var field : type.getDeclaredFields()) {
                Column column = field.getAnnotation(Column.class);
                if (column != null && byColumn.containsKey(column.name().toLowerCase(java.util.Locale.ROOT))) {
                    byProperty.putIfAbsent(field.getName(), byColumn.get(column.name().toLowerCase(java.util.Locale.ROOT)));
                }
            }
        }
        return byProperty;
    }

    private static String schemaName(Class<?> record) {
        Schema named = record.getAnnotation(Schema.class);
        return named != null && !named.name().isEmpty() ? named.name() : record.getSimpleName();
    }

    private static String simpleName(Class<?> type) {
        return type == null ? "no entity" : type.getSimpleName();
    }
}
