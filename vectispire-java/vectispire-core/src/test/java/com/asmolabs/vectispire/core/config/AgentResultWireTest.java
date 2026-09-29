package com.asmolabs.vectispire.core.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A remote agent's result, read by the control plane's own mapper.
 *
 * <p><b>Why this exists.</b> {@code ScanArtifacts} is a record of {@code Optional}s, and Jackson 2
 * handles an {@code Optional} only through the {@code jdk8} module, which neither side registered.
 * The agent could not write a result and the control plane could not read one: every remote scan
 * ended in "The result could not be serialized" on the agent, and a body written by hand came back
 * 400. The only route test sent {@code {}}, which has no {@code Optional} in it to fail on. The
 * agent's half is {@code AgentWireFormatTest}; the two must describe the same document.
 */
@DisplayName("the control plane reads the result an agent writes")
class AgentResultWireTest {

    private final ObjectMapper json = new CoreConfiguration().objectMapper();

    /** What the agent writes today, as its own test pins it. */
    private static final String AGENT_BODY = """
            {"sbom":null,"project":null,"dependencies":[],"secrets":null,"iac":null,"sast":null,
             "apiEndpoints":null,"apiContracts":null,
             "failures":[{"step":"secrets","reason":"gitleaks exited 2"}],
             "duration":"PT12.345S"}
            """;

    @Test
    @DisplayName("empty stays \"ran, found nothing\" and null stays \"did not look\" (decision 0007)")
    void absentAndEmptySurviveTheWire() throws Exception {
        ScanArtifacts read = json.readValue(AGENT_BODY, ScanArtifacts.class);

        assertThat(read.dependencies()).contains(List.of());
        assertThat(read.secrets()).isEmpty();
        // A JSON null into a JsonNode is a NullNode, which is present: "no SBOM" arrived as one.
        assertThat(read.sbom()).isEmpty();
        assertThat(read.failures()).containsExactly(new ScanArtifacts.Failure("secrets", "gitleaks exited 2"));
        assertThat(read.duration()).isEqualTo(Duration.ofMillis(12_345));
    }

    @Test
    @DisplayName("a field an older agent leaves out reads as \"did not look\", never as a null that breaks ingestion")
    void aMissingFieldIsAbsent() throws Exception {
        ScanArtifacts read = json.readValue("{\"dependencies\":[],\"failures\":[],\"duration\":\"PT1S\"}",
                ScanArtifacts.class);

        assertThat(read.sast()).isNotNull().isEmpty();
        assertThat(read.apiContracts()).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("the tree's languages cross as names: missing is unknown, [] is none, a newer name fails nothing")
    void languagesSurviveTheWire() throws Exception {
        assertThat(json.readValue(AGENT_BODY, ScanArtifacts.class).languages())
                .describedAs("an agent older than the census's record did not send one: unknown")
                .isEmpty();
        assertThat(json.readValue("{\"languages\":[],\"failures\":[]}", ScanArtifacts.class).languages())
                .contains(java.util.Set.of());
        assertThat(json.readValue("{\"languages\":[\"java\",null,\"zig\"],\"failures\":[]}", ScanArtifacts.class)
                        .languages())
                .describedAs("a language only a newer agent knows is carried, and dropped when written, not a 400")
                .contains(java.util.Set.of("java", "zig"));
        String written = json.writeValueAsString(ScanArtifacts.builder()
                .languages(java.util.Set.of(com.asmolabs.vectispire.common.domain.plugins.Language.KOTLIN))
                .build(Duration.ZERO));
        assertThat(json.readTree(written).path("languages").path(0).asText()).isEqualTo("kotlin");
    }

    @Test
    @DisplayName("a duration written as seconds by an agent from before the contract was pinned is still read")
    void aLegacyNumericDurationIsSeconds() throws Exception {
        ScanArtifacts read = json.readValue("{\"failures\":[],\"duration\":12.345000000}", ScanArtifacts.class);

        assertThat(read.duration()).isEqualTo(Duration.ofMillis(12_345));
    }

    @Test
    @DisplayName("a plugin's three states cross the wire as the agent writes them, and a lost list arrives absent")
    void pluginStates() throws Exception {
        String body = """
                {"plugins":[
                  {"state":"produced","pluginId":"acme-lint","manifestDigest":"d1","toolName":"acme","toolVersion":"4.2",
                   "findings":[{"ruleId":"ACME001","severity":"HIGH","file":"src/a.py","line":3,"message":"m"}]},
                  {"state":"produced","pluginId":"clean","manifestDigest":"d2","toolName":"acme","findings":[]},
                  {"state":"not_applicable","pluginId":"java-only","manifestDigest":"d3","languages":["java"]},
                  {"state":"absent","pluginId":"broken","manifestDigest":"d4","reason":"exited with 2"},
                  {"state":"produced","pluginId":"lost","manifestDigest":"d5","toolName":"acme"}],
                 "failures":[],"duration":"PT1S"}
                """;

        ScanArtifacts read = json.readValue(body, ScanArtifacts.class);

        assertThat(read.plugins()).extracting(step -> step.getClass().getSimpleName())
                .containsExactly("Produced", "Produced", "NotApplicable", "Absent", "Absent");
        assertThat(((com.asmolabs.vectispire.common.scanning.PluginStep.Produced) read.plugins().get(1)).findings())
                .as("an empty list stays \"ran, found nothing\"")
                .isEmpty();
        assertThat(json.readValue(json.writeValueAsString(read), ScanArtifacts.class)).isEqualTo(read);
    }

    @Test
    @DisplayName("what the control plane would write, it reads back unchanged")
    void aRoundTripIsTheIdentity() throws Exception {
        ScanArtifacts written = ScanArtifacts.builder()
                .dependencies(List.of())
                .failed("sast", "semgrep timed out")
                .build(Duration.ofSeconds(90));

        String body = json.writeValueAsString(written);

        assertThat(json.readTree(body).path("duration").asText()).isEqualTo("PT1M30S");
        assertThat(json.readValue(body, ScanArtifacts.class)).isEqualTo(written);
    }
}
