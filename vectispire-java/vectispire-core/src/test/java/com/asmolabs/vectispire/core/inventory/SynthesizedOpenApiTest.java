package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.inventory.persistence.ApiContractRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ApiEndpointEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ApiEndpointRepository;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The OpenAPI document synthesized from a repository's discovered endpoints, read back by a strict
 * parser: one that refuses a duplicate key, which a lenient one would silently resolve to the last.
 */
@DisplayName("the synthesized OpenAPI document")
class SynthesizedOpenApiTest {

    private static final long REPOSITORY = 7L;

    /** Strict: a key twice in one object is an error, as RFC 8259 leaves to the reader and OpenAPI forbids. */
    private static final ObjectMapper STRICT =
            new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    private final ApiEndpointRepository endpoints = mock(ApiEndpointRepository.class);

    private long nextId = 1;

    @Test
    @DisplayName("a path and a summary carrying a control character and a quote stay valid JSON, and read back as written")
    void controlCharactersAndQuotes() throws Exception {
        String path = "/api/v1/\"quoted\"\tpath";
        String summary = "Lists \"everything\"\nacross\u0001lines \\ and more";
        JsonNode document = synthesize(endpoint("GET", path, summary, null));

        assertThat(document.at("/paths").get(path).get("get").get("summary").asText()).isEqualTo(summary);
    }

    @Test
    @DisplayName("two methods on one path are one path item, and a method two scans saw is one operation, the latest")
    void twoVerbsOnOnePath() throws Exception {
        ApiEndpointEntity first = endpoint("GET", "/api/v1/users", "first scan", null);
        ApiEndpointEntity create = endpoint("POST", "/api/v1/users", "create", null);
        ApiEndpointEntity second = endpoint("GET", "/api/v1/users", "second scan", null);
        // In no particular order within a path, as the repository's query sorts by path alone.
        JsonNode document = synthesize(second, create, first);

        JsonNode item = document.at("/paths").get("/api/v1/users");
        assertThat(fieldNames(item)).containsExactly("get", "post");
        assertThat(item.get("get").get("summary").asText()).isEqualTo("second scan");
        assertThat(document.at("/paths").size()).isEqualTo(1);
    }

    @Test
    @DisplayName("a handler for any method is every operation the path does not declare, and no second get")
    void anyMethod() throws Exception {
        JsonNode document = synthesize(
                endpoint("GET", "/api/v1/items", "declared get", "listItems"),
                endpoint("ALL", "/api/v1/items", "catch-all", "items"),
                endpoint("ALL", "/health", null, null));

        JsonNode items = document.at("/paths").get("/api/v1/items");
        assertThat(fieldNames(items)).containsExactly("get", "put", "post", "delete", "options", "head", "patch", "trace");
        assertThat(items.get("get").get("summary").asText()).isEqualTo("declared get");
        assertThat(items.get("post").get("summary").asText()).isEqualTo("catch-all (any method)");
        assertThat(items.get("post").get("operationId").asText()).isEqualTo("items_post");
        assertThat(fieldNames(document.at("/paths").get("/health"))).hasSize(8);

        // OpenAPI requires every operationId to be unique in the document.
        List<String> ids = new ArrayList<>();
        document.at("/paths").forEach(item -> item.forEach(operation -> ids.add(operation.get("operationId").asText())));
        assertThat(ids).doesNotHaveDuplicates().hasSize(16);
    }

    @Test
    @DisplayName("two handlers sharing a method name keep distinct operationIds")
    void sharedOperationNames() throws Exception {
        JsonNode document = synthesize(
                endpoint("GET", "/api/v1/orders", "orders", "list"),
                endpoint("GET", "/api/v1/users", "users", "list"));

        assertThat(document.at("/paths").get("/api/v1/orders").get("get").get("operationId").asText()).isEqualTo("list");
        assertThat(document.at("/paths").get("/api/v1/users").get("get").get("operationId").asText()).isEqualTo("list_2");
    }

    private JsonNode synthesize(ApiEndpointEntity... rows) throws Exception {
        when(endpoints.findByRepositoryIdOrderByPathAsc(REPOSITORY)).thenReturn(List.of(rows));
        ApiInventoryService service =
                new ApiInventoryService(endpoints, mock(ApiContractRepository.class), Clock.systemUTC());
        String json = service.exportSynthesizedOpenApiJson(new VisibleTarget<>(new ScanTarget.Repository(REPOSITORY)));
        JsonNode document = STRICT.readTree(json);
        assertThat(document.get("openapi").asText()).isEqualTo("3.0.3");
        return document;
    }

    private ApiEndpointEntity endpoint(String method, String path, String summary, String operationId) {
        ApiEndpointEntity endpoint = new ApiEndpointEntity();
        endpoint.setId(nextId++);
        endpoint.setRepositoryId(REPOSITORY);
        endpoint.setHttpMethod(method);
        endpoint.setPath(path);
        endpoint.setSummary(summary);
        endpoint.setOperationId(operationId);
        endpoint.setFilePath("src/Routes.java");
        return endpoint;
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
