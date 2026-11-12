package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The result bodies the Rust agent writes ({@code artifacts/rust-written.json}), read with the agent's
 * mapper and written back.
 *
 * <p><b>The tree written back must be the tree received.</b> A step the Rust agent sent as absent and
 * this side read as empty — or the reverse — would resolve or keep a backlog the scan never decided
 * (decision 0007), and only this side's reader can show it. The mapper is built as
 * {@code VectispireAgentApplication} and the control plane's {@code CoreConfiguration} build theirs:
 * both sides of the protocol must read a body the same way, and that is what is held here.
 *
 * <p>A set of languages has no order on this side ({@code Set.copyOf}), so the two trees are compared
 * with each {@code languages} array sorted; everything else is compared as it is.
 */
class ScanArtifactsReferenceSetTest {

    private static final ObjectMapper AGENT = JsonMapper.builder()
            .addModule(new JavaTimeModule())
            .addModule(new Jdk8Module())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    @Test
    void whatTheRustAgentSendsIsReadAsItMeantIt() throws Exception {
        JsonNode cases = AGENT.readTree(ReferenceSet.read("artifacts/rust-written.json"));
        assertThat(cases.size()).as("cases in artifacts/rust-written.json").isGreaterThanOrEqualTo(4);
        for (JsonNode entry : cases) {
            String name = entry.path("name").asText();
            String body = entry.path("body").asText();
            ScanArtifacts read = AGENT.readValue(body, ScanArtifacts.class);
            JsonNode sent = normalised(AGENT.readTree(body));
            JsonNode rewritten = normalised(AGENT.readTree(AGENT.writeValueAsString(read)));
            assertThat(rewritten).as("%s, read and written back by the agent's mapper", name).isEqualTo(sent);
        }
    }

    @Test
    void absentAndEmptyArriveApart() throws Exception {
        ScanArtifacts nothing = case_("nothing-ran");
        assertThat(nothing.observedNothing()).isTrue();
        assertThat(nothing.secrets()).isEmpty();
        assertThat(nothing.languages()).isEmpty();
        assertThat(nothing.duration()).isEqualTo(Duration.ZERO);

        ScanArtifacts empty = case_("everything-ran-and-found-nothing");
        assertThat(empty.observedNothing()).isFalse();
        assertThat(empty.secrets()).hasValue(List.of());
        assertThat(empty.dependencies()).hasValue(List.of());
        assertThat(empty.languages()).hasValueSatisfying(set -> assertThat(set).isEmpty());
        assertThat(empty.sbom()).isPresent();

        ScanArtifacts partial = case_("some-steps-absent-with-their-failures");
        assertThat(partial.secrets()).hasValueSatisfying(list -> assertThat(list).hasSize(1));
        assertThat(partial.dependencies()).isEmpty();
        assertThat(partial.failures()).extracting(ScanArtifacts.Failure::step).containsExactly("dependencies", "sast");
        assertThat(partial.duration()).isEqualTo(Duration.ofMillis(12_345));

        ScanArtifacts full = case_("every-finding-type-and-plugin-state");
        assertThat(full.plugins()).extracting(step -> step.getClass().getSimpleName())
                .containsExactly("Produced", "Produced", "NotApplicable", "Absent", "Refused");
        assertThat(full.duration()).isEqualTo(Duration.ofMillis(3_723_500));
    }

    private static ScanArtifacts case_(String name) throws Exception {
        for (JsonNode entry : AGENT.readTree(ReferenceSet.read("artifacts/rust-written.json"))) {
            if (entry.path("name").asText().equals(name)) {
                return AGENT.readValue(entry.path("body").asText(), ScanArtifacts.class);
            }
        }
        throw new AssertionError("no case " + name + " in artifacts/rust-written.json");
    }

    /** Each {@code languages} array sorted, wherever it is — the one place order carries nothing. */
    private static JsonNode normalised(JsonNode node) {
        if (node instanceof ObjectNode object) {
            object.properties().forEach(field -> {
                JsonNode value = field.getValue();
                if (field.getKey().equals("languages") && value instanceof ArrayNode array) {
                    List<JsonNode> sorted = new ArrayList<>();
                    array.forEach(sorted::add);
                    sorted.sort(Comparator.comparing(JsonNode::asText));
                    array.removeAll();
                    sorted.forEach(array::add);
                } else {
                    normalised(value);
                }
            });
        } else if (node instanceof ArrayNode array) {
            array.forEach(ScanArtifactsReferenceSetTest::normalised);
        }
        return node;
    }
}
