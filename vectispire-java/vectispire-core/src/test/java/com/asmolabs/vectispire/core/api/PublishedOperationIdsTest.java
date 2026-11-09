package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The operation ids a client generated from {@code openapi.json} calls by name, held where they were
 * published.
 *
 * <h2>Why this exists</h2>
 *
 * <p>Springdoc names an operation after its handler method and, when two methods share a name, numbers
 * the later ones in the order it walks the paths ({@code list}, {@code list_1} … {@code list_23}). A new
 * route called {@code list} that the walk meets first takes the number of an old one and pushes every
 * following one a place along: the integrations' registry, written for 0.12, did exactly that, and the
 * audit log's {@code list_22} became {@code list_23} with no route of the audit log changed. {@link
 * ClientContractSpecTest} saw it and was satisfied by the regeneration, because it detects a change and
 * cannot tell an addition from a break. Decision 0043 (§1) makes the API additive; for a generated
 * client an operation id is part of it.
 *
 * <h2>Why a baseline file, and why the served document</h2>
 *
 * <p>The baseline is {@code openapi/published-operation-ids.txt}, a copy of the ids as published, not the
 * committed {@code openapi.json}: that file is rewritten by the flag that regenerates it, so comparing
 * with it would bless the shift the moment someone regenerated. The comparison reads the document the
 * application serves, so a missing {@code operationId} on a new route fails here at once, whatever state
 * the committed file is in.
 *
 * <p>The second rule keeps the numbering from moving again: an operation the baseline does not know may
 * not carry a springdoc number. A new route whose method name collides names its id
 * ({@code @Operation(operationId = …)}), so it takes no place in anyone's count.
 */
@DisplayName("the published operation ids")
class PublishedOperationIdsTest extends ApiTestBase {

    private static final String BASELINE = "/openapi/published-operation-ids.txt";

    /** What springdoc appends to the second and later methods of one name. */
    private static final Pattern GENERATED_SUFFIX = Pattern.compile(".+_\\d+");

    @Test
    @DisplayName("keep every id the baseline publishes, on the same method and path")
    void keep_every_published_id() throws Exception {
        Map<String, String> served = servedIds();
        List<String> moved = new ArrayList<>();
        baseline().forEach((operation, id) -> {
            String now = served.get(operation);
            if (!id.equals(now)) {
                moved.add(operation + ": published " + id + ", now " + (now == null ? "absent" : now));
            }
        });

        assertThat(moved)
                .as("""
                        A published operation id moved or disappeared. A client generated from openapi.json \
                        calls it by name, so this breaks it with no route of its own changed (decision 0043, \
                        §1). Give the route that took the id its own: @Operation(operationId = "…"). Never \
                        edit the baseline to match.""")
                .isEmpty();
    }

    @Test
    @DisplayName("let no new operation take a numbered id")
    void no_new_operation_takes_a_numbered_id() throws Exception {
        Map<String, String> published = baseline();
        List<String> numbered = servedIds().entrySet().stream()
                .filter(e -> !published.containsKey(e.getKey()))
                .filter(e -> GENERATED_SUFFIX.matcher(e.getValue()).matches())
                .map(e -> e.getKey() + ": " + e.getValue())
                .toList();

        assertThat(numbered)
                .as("""
                        A new operation was numbered by springdoc: its handler method shares a name with \
                        another route's, and the number depends on the order the paths are walked — the next \
                        route added can move it. Name it: @Operation(operationId = "…").""")
                .isEmpty();
    }

    /** {@code "GET /api/v1/audit-log"} → its operation id, as the application serves the document. */
    private Map<String, String> servedIds() throws Exception {
        JsonNode document = json.readTree(mvc.perform(authenticated(get("/v3/api-docs"), asReader()))
                .andReturn()
                .getResponse()
                .getContentAsString());
        Map<String, String> ids = new LinkedHashMap<>();
        document.path("paths").properties().forEach(path -> path.getValue().properties().forEach(method -> {
            JsonNode id = method.getValue().get("operationId");
            if (id != null) {
                ids.put(method.getKey().toUpperCase(Locale.ROOT) + " " + path.getKey(), id.asText());
            }
        }));
        assertThat(ids).as("the served document lists no operation at all").isNotEmpty();
        return ids;
    }

    private static Map<String, String> baseline() throws IOException {
        Map<String, String> ids = new LinkedHashMap<>();
        try (InputStream in = PublishedOperationIdsTest.class.getResourceAsStream(BASELINE)) {
            assertThat(in).as("%s is missing from the test resources", BASELINE).isNotNull();
            for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] fields = line.trim().split(" ");
                assertThat(fields).as("baseline line '%s' is not 'METHOD path id'", line).hasSize(3);
                ids.put(fields[0] + " " + fields[1], fields[2]);
            }
        }
        return ids;
    }
}
