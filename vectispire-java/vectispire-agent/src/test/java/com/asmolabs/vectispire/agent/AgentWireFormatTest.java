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
    @DisplayName("a plugin's three states leave the agent with their discriminator, and a task's plugins are read")
    void pluginsOnTheWire() throws Exception {
        String digest = "e".repeat(64);
        JsonNode written = json.readTree(json.writeValueAsString(ScanArtifacts.builder()
                .plugin(new com.asmolabs.vectispire.common.scanning.PluginStep.Produced("a", digest, "t", "1", java.util.List.of()))
                .plugin(new com.asmolabs.vectispire.common.scanning.PluginStep.NotApplicable("b", digest,
                        java.util.Set.of(com.asmolabs.vectispire.common.domain.plugins.Language.GO)))
                .plugin(new com.asmolabs.vectispire.common.scanning.PluginStep.Absent("c", digest, "exit 2"))
                .plugin(new com.asmolabs.vectispire.common.scanning.PluginStep.Refused("d", digest,
                        com.asmolabs.vectispire.common.scanning.PluginStep.Refusal.UNSIGNED, "no signer declared"))
                .plugin(new com.asmolabs.vectispire.common.scanning.PluginStep.Produced("e", digest, "t", "1",
                        java.util.List.of(), com.asmolabs.vectispire.common.scanning.PluginStep.Signature.WAIVED))
                .build(Duration.ZERO)));

        assertThat(written.path("plugins")).extracting(node -> node.path("state").asText())
                .containsExactly("produced", "not_applicable", "absent", "refused", "produced");
        assertThat(written.path("plugins").path(3).path("refusal").asText()).isEqualTo("unsigned");
        assertThat(written.path("plugins").path(4).path("signature").asText()).isEqualTo("waived");
        assertThat(written.path("plugins").path(0).path("findings").isArray())
                .as("an empty list is written as one: it is the claim \"ran, found nothing\"")
                .isTrue();

        com.asmolabs.vectispire.common.scanning.ScanTask task = json.readValue(
                "{\"target\":{\"kind\":\"repository\",\"url\":\"https://h/p.git\",\"branch\":\"main\"},"
                        + "\"steps\":[],\"plugins\":[{\"id\":\"a\",\"digest\":\"" + digest + "\"},"
                        + "{\"id\":\"b\",\"digest\":\"" + digest + "\",\"runsUnsigned\":true}]}",
                com.asmolabs.vectispire.common.scanning.ScanTask.class);
        assertThat(task.plugins()).containsExactly(
                new com.asmolabs.vectispire.common.domain.plugins.PluginRef("a", digest),
                new com.asmolabs.vectispire.common.domain.plugins.PluginRef("b", digest, true));
    }

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
     * A claim's answer through the agent's own mapper, as the control plane now writes it — with the
     * attempt — and as an older one did, without: the second must still be read, as a task whose
     * failure there is nowhere to report.
     */
    @Test
    @DisplayName("a claim is read with its attempt, and without one from an older control plane")
    void aClaimIsReadWithOrWithoutItsAttempt() throws Exception {
        String task = json.writeValueAsString(new com.asmolabs.vectispire.common.scanning.ScanTask(
                new com.asmolabs.vectispire.common.scanning.ScanTask.Target.Image(
                        new com.asmolabs.vectispire.common.domain.targets.ImageReference("docker.io", "library/alpine", "3"),
                        null),
                null,
                java.util.Set.of(com.asmolabs.vectispire.common.scanning.ScanTask.Step.DEPENDENCIES)));

        AgentProtocol.AssignedTask current =
                json.readValue("{\"scanId\":7,\"attempt\":2,\"task\":" + task + "}", AgentProtocol.AssignedTask.class);
        AgentProtocol.AssignedTask older =
                json.readValue("{\"scanId\":7,\"task\":" + task + "}", AgentProtocol.AssignedTask.class);

        assertThat(current.scanId()).isEqualTo(7L);
        assertThat(current.attempt()).isEqualTo(2);
        assertThat(current.task()).isNotNull();
        assertThat(older.attempt()).isNull();
        assertThat(older.task()).isNotNull();
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
