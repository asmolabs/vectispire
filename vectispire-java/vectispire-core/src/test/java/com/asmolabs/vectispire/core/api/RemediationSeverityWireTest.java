package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The severity list copied into {@link RemediationDistributionView}, kept current by force.
 *
 * <p><b>An accessor returning a {@code String} leaves springdoc nothing to enumerate</b>, so the
 * six values are written by hand in {@code @Schema} to keep the document's enumeration. A copied
 * list drifts: the day {@link Severity} gains a constant, this document would announce a set of
 * values the server can exceed, and a client would be right to rely on it.
 *
 * <p>This test is the counterpart of the copy. It does not check that the list is "correct" in the
 * sense of an opinion: it checks that it is exactly the domain's enumeration, in the form this API
 * uses.
 */
@DisplayName("the severities the distribution publishes")
class RemediationSeverityWireTest extends ApiTestBase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    @DisplayName("are the domain's enumeration, lowercase, on both fields")
    void match_the_domain_enum() throws Exception {
        JsonNode schemas = MAPPER.readTree(mvc.perform(authenticated(get("/v3/api-docs"), asReader()))
                        .andReturn()
                        .getResponse()
                        .getContentAsString())
                .get("components")
                .get("schemas");

        List<String> expected =
                Arrays.stream(Severity.values()).map(Severity::wireName).toList();

        assertThat(enumOf(schemas, "BySeverityView", "severity"))
                .as("a row's severity")
                .containsExactlyInAnyOrderElementsOf(expected);
        assertThat(enumOf(schemas, "RemediationDistributionView", "oldestOpenSeverity"))
                .as("the oldest open item's severity")
                .containsExactlyInAnyOrderElementsOf(expected);
    }

    /**
     * <b>Lowercase, said separately.</b> The assertion above would still pass if both lists were
     * uppercase and {@code wireName()} with them — and the spelling is precisely what was wrong on
     * this route, and on it alone.
     */
    @Test
    @DisplayName("are lowercase, as everywhere else in this API")
    void are_lowercase() {
        assertThat(Arrays.stream(Severity.values()).map(Severity::wireName))
                .allSatisfy(name -> assertThat(name).isEqualTo(name.toLowerCase(java.util.Locale.ROOT)));
    }

    private static List<String> enumOf(JsonNode schemas, String schema, String property) {
        JsonNode values = schemas.get(schema).get("properties").get(property).get("enum");
        assertThat(values).as("%s.%s publishes an enumeration", schema, property).isNotNull();
        List<String> names = new ArrayList<>();
        values.forEach(value -> names.add(value.asText()));
        return names;
    }
}
