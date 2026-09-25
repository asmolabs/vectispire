package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What the agent's own mapper puts on the wire, measured against the published contract.
 *
 * <p><b>Why the real bean.</b> The contract (openapi.json) declares {@code ScanArtifacts.duration}
 * as {@code string, format: duration} — ISO-8601. Jackson's {@code JavaTimeModule} writes a
 * {@code Duration} as a decimal number of seconds unless told otherwise, and
 * {@code WRITE_DATES_AS_TIMESTAMPS}, which both mappers disable, does not govern durations. The
 * control plane's lenient reader accepted either, so nothing failed; only a client generated from
 * the contract would have. A mapper assembled in the test would prove the test's configuration.
 */
@DisplayName("the agent writes what the contract publishes")
class AgentWireFormatTest {

    private final ObjectMapper json = new VectispireAgentApplication().objectMapper();

    @Test
    @DisplayName("a scan's duration leaves the agent as ISO-8601 text, the contract's \"format: duration\"")
    void aDurationIsIsoText() throws Exception {
        JsonNode written = json.readTree(json.writeValueAsString(
                ScanArtifacts.builder().build(Duration.ofMillis(12_345))));

        assertThat(written.path("duration").isTextual())
                .as("duration was written as %s", written.path("duration"))
                .isTrue();
        assertThat(written.path("duration").asText()).isEqualTo("PT12.345S");
    }

    /**
     * The result could not be written at all: {@code ScanArtifacts} is a record of
     * {@code Optional}s, Jackson 2 refuses one without the {@code jdk8} module, and every remote
     * scan ended in "The result could not be serialized". {@code AgentProtocolTest} mocks the
     * transport and never saw it.
     */
    @Test
    @DisplayName("a result is written at all, with \"found nothing\" as [] and \"did not look\" as null")
    void absentAndEmptyAreWrittenApart() throws Exception {
        JsonNode written = json.readTree(json.writeValueAsString(
                ScanArtifacts.builder().dependencies(java.util.List.of()).build(Duration.ofSeconds(1))));

        assertThat(written.path("dependencies").isArray()).isTrue();
        assertThat(written.path("dependencies")).isEmpty();
        assertThat(written.path("secrets").isNull()).isTrue();
    }
}
