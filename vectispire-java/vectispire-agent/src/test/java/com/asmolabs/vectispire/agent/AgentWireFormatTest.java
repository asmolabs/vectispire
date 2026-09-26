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
     * The sealing key announcement, as the agent's own mapper writes it — what {@code AgentHttp}
     * does with the body — against the names and types the control plane's {@code SealingKeyRequest}
     * declares: {@code public_key}, a {@code generation} that is a number past 32 bits, and a
     * signature that still verifies once it has been through the mapper.
     */
    @Test
    @DisplayName("a sealing key announcement leaves as public_key, a numeric generation, and a signature that verifies")
    @SuppressWarnings("unchecked")
    void aSealingKeyAnnouncementIsWrittenAsTheContractSays() throws Exception {
        java.util.UUID agent = java.util.UUID.randomUUID();
        long generation = 1_790_380_800_000L;
        var signing = com.asmolabs.vectispire.common.domain.crypto.ResultAttestation.generate();
        var pair = new com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope().generateKeyPair();
        AgentHttp http = org.mockito.Mockito.mock(AgentHttp.class);
        org.mockito.Mockito.when(http.call(org.mockito.ArgumentMatchers.eq("/api/v1/agent/hello"),
                        org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any()))
                .thenReturn(new AgentHttp.Response(200, json.readTree(
                        "{\"id\":\"" + agent + "\",\"name\":\"edge\",\"contractVersion\":\"1\",\"maxConcurrent\":1,"
                                + "\"credentialsMode\":\"delegated\"}")));
        org.mockito.Mockito.when(http.call(org.mockito.ArgumentMatchers.eq("/api/v1/agent/sealing-key"),
                        org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.any()))
                .thenReturn(new AgentHttp.Response(204, json.nullNode()));
        AgentProtocol protocol = new AgentProtocol(http, json, pair, signing.privateKey(), generation);
        protocol.hello(new AgentProtocol.Description("host", "linux", "1", "docker"));
        protocol.announceSealingKey();

        var body = org.mockito.ArgumentCaptor.forClass(Object.class);
        org.mockito.Mockito.verify(http).call(org.mockito.ArgumentMatchers.eq("/api/v1/agent/sealing-key"),
                org.mockito.ArgumentMatchers.eq("POST"), body.capture(), org.mockito.ArgumentMatchers.any());
        JsonNode written = json.readTree(json.writeValueAsString(body.getValue()));

        assertThat(written.path("public_key").asText()).isEqualTo(pair.publicKey());
        assertThat(written.path("generation").isIntegralNumber())
                .as("generation was written as %s", written.path("generation"))
                .isTrue();
        assertThat(written.path("generation").asLong()).isEqualTo(generation);
        assertThat(com.asmolabs.vectispire.common.domain.crypto.SealingKeyAttestation.verify(
                        signing.publicKey(), agent, written.path("generation").asLong(),
                        written.path("public_key").asText(), written.path("signature").asText()))
                .isTrue();
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
