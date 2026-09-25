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
    @DisplayName("a duration written as seconds by an agent from before the contract was pinned is still read")
    void aLegacyNumericDurationIsSeconds() throws Exception {
        ScanArtifacts read = json.readValue("{\"failures\":[],\"duration\":12.345000000}", ScanArtifacts.class);

        assertThat(read.duration()).isEqualTo(Duration.ofMillis(12_345));
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
