package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.plugins.PluginRef;
import com.asmolabs.vectispire.common.domain.sarif.SarifFinding;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The plugin half of the agent protocol, through a mapper configured as both sides configure theirs.
 * The control plane's and the agent's own mappers are exercised by {@code AgentResultWireTest} and
 * {@code AgentWireFormatTest}; this one keeps the shape honest where it is declared.
 */
@DisplayName("plugins on the wire")
class PluginWireTest {

    private final ObjectMapper json = new ObjectMapper()
            .registerModule(new Jdk8Module())
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    private static final String DIGEST = "sha256:" + "e".repeat(64);

    @Test
    @DisplayName("the three states cross with their discriminator and come back as they left")
    void threeStates() throws Exception {
        ScanArtifacts written = ScanArtifacts.builder()
                .plugin(new PluginStep.Produced("a", DIGEST, "acme", "1.0",
                        List.of(new SarifFinding("R1", Severity.HIGH, "src/a.py", 3, "m"))))
                .plugin(new PluginStep.Produced("empty", DIGEST, "acme", null, List.of()))
                .plugin(new PluginStep.NotApplicable("b", DIGEST, Set.of(Language.JAVA)))
                .plugin(new PluginStep.Absent("c", DIGEST, "exited with 2"))
                .build(Duration.ofSeconds(1));

        String body = json.writeValueAsString(written);
        JsonNode tree = json.readTree(body);

        assertThat(tree.path("plugins")).extracting(node -> node.path("state").asText())
                .containsExactly("produced", "produced", "not_applicable", "absent");
        assertThat(tree.path("plugins").path(2).path("languages").path(0).asText()).isEqualTo("java");
        assertThat(json.readValue(body, ScanArtifacts.class)).isEqualTo(written);
    }

    @Test
    @DisplayName("the tree's languages cross as wire names; missing or null is unknown, [] is none")
    void languages() throws Exception {
        ScanArtifacts written = ScanArtifacts.builder()
                .languages(Set.of(Language.JAVA, Language.TYPESCRIPT))
                .build(Duration.ofSeconds(1));
        String body = json.writeValueAsString(written);

        assertThat(json.readTree(body).path("languages")).extracting(JsonNode::asText)
                .containsExactlyInAnyOrder("java", "typescript");
        assertThat(json.readValue(body, ScanArtifacts.class).languages()).contains(Set.of("java", "typescript"));
        assertThat(json.readValue("{\"failures\":[],\"duration\":\"PT1S\"}", ScanArtifacts.class).languages())
                .describedAs("an agent older than the field did not count: unknown")
                .isEmpty();
        assertThat(json.readValue("{\"languages\":null,\"failures\":[]}", ScanArtifacts.class).languages())
                .isEmpty();
        assertThat(json.readValue("{\"languages\":[],\"failures\":[]}", ScanArtifacts.class).languages())
                .describedAs("counted, and no file said a language")
                .contains(Set.of());
        assertThat(json.readValue("{\"languages\":[\"java\",\"zig\"],\"failures\":[]}", ScanArtifacts.class)
                        .languages())
                .describedAs("a name a newer executor knows does not fail the result it travels in")
                .contains(Set.of("java", "zig"));
    }

    @Test
    @DisplayName("a result from an agent older than plugins carries none, and none is read — not an empty run")
    void olderAgent() throws Exception {
        ScanArtifacts read = json.readValue("{\"failures\":[],\"duration\":\"PT1S\"}", ScanArtifacts.class);

        assertThat(read.plugins()).isEmpty();
    }

    @Test
    @DisplayName("a produced step that lost its findings on the way arrives absent, never as \"ran, found nothing\"")
    void lostFindings() throws Exception {
        ScanArtifacts read = json.readValue("{\"plugins\":[{\"state\":\"produced\",\"pluginId\":\"a\",\"manifestDigest\":\"d\","
                + "\"toolName\":\"t\"}],\"failures\":[],\"duration\":\"PT1S\"}", ScanArtifacts.class);

        assertThat(read.plugins()).singleElement().isInstanceOf(PluginStep.Absent.class);
    }

    @Test
    @DisplayName("the task carries its plugins by id and digest, and a task without them reads as none")
    void task() throws Exception {
        ScanTask written = new ScanTask(new ScanTask.Target.Repository("https://host/p.git", "main", null, null), null,
                Set.of(ScanTask.Step.SAST), List.of(new PluginRef("acme-lint", DIGEST)));

        String body = json.writeValueAsString(written);

        assertThat(json.readTree(body).path("plugins").path(0).path("digest").asText()).isEqualTo(DIGEST);
        assertThat(json.readValue(body, ScanTask.class)).isEqualTo(written);
        assertThat(json.readValue("{\"target\":{\"kind\":\"repository\",\"url\":\"u\",\"branch\":\"b\"},\"steps\":[]}",
                        ScanTask.class).plugins())
                .isEmpty();
    }
    @Test
    @DisplayName("a refusal crosses with its reason, a produced step with its signer's footing, and unknown tokens do not fail the result")
    void refusalsAndSignatures() throws Exception {
        ScanArtifacts written = ScanArtifacts.builder()
                .plugin(new PluginStep.Refused("u", DIGEST, PluginStep.Refusal.UNSIGNED, "no signer declared"))
                .plugin(new PluginStep.Refused("v", DIGEST, PluginStep.Refusal.SIGNATURE_UNVERIFIED, "cosign: no match"))
                .plugin(new PluginStep.Produced("w", DIGEST, "acme", null, List.of(), PluginStep.Signature.WAIVED))
                .build(Duration.ofSeconds(1));

        String body = json.writeValueAsString(written);
        JsonNode tree = json.readTree(body);

        assertThat(tree.path("plugins")).extracting(node -> node.path("state").asText())
                .containsExactly("refused", "refused", "produced");
        assertThat(tree.path("plugins").path(0).path("refusal").asText()).isEqualTo("unsigned");
        assertThat(tree.path("plugins").path(1).path("refusal").asText()).isEqualTo("signature_unverified");
        assertThat(tree.path("plugins").path(2).path("signature").asText()).isEqualTo("waived");
        assertThat(json.readValue(body, ScanArtifacts.class)).isEqualTo(written);

        ScanArtifacts later = json.readValue("{\"plugins\":[{\"state\":\"refused\",\"pluginId\":\"x\",\"refusal\":"
                + "\"quantum_unsafe\",\"reason\":\"r\"},{\"state\":\"produced\",\"pluginId\":\"y\",\"findings\":[],"
                + "\"signature\":\"notarised\"}],\"failures\":[]}", ScanArtifacts.class);
        assertThat(later.plugins().getFirst()).isInstanceOfSatisfying(PluginStep.Refused.class, refused ->
                assertThat(refused.refusal()).as("a reason a newer executor names is still a refusal").isNull());
        assertThat(later.plugins().get(1)).isInstanceOfSatisfying(PluginStep.Produced.class, produced ->
                assertThat(produced.signature()).isNull());
    }

    @Test
    @DisplayName("the task carries a plugin's waiver, and a task from before the field carries none")
    void waiverOnTheTask() throws Exception {
        ScanTask written = new ScanTask(new ScanTask.Target.Repository("https://host/p.git", "main", null, null), null,
                Set.of(), List.of(new PluginRef("acme-lint", DIGEST, true)));

        String body = json.writeValueAsString(written);

        assertThat(json.readTree(body).path("plugins").path(0).path("runsUnsigned").asBoolean()).isTrue();
        assertThat(json.readValue(body, ScanTask.class)).isEqualTo(written);
        assertThat(json.readValue("{\"target\":{\"kind\":\"repository\",\"url\":\"u\",\"branch\":\"b\"},\"steps\":[],"
                        + "\"plugins\":[{\"id\":\"a\",\"digest\":\"d\"}]}", ScanTask.class).plugins())
                .containsExactly(new PluginRef("a", "d", false));
    }
}
