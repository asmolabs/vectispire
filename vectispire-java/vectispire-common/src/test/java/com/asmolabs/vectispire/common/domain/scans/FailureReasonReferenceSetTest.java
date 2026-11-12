package com.asmolabs.vectispire.common.domain.scans;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * What {@link FailureReason#scrub} leaves of a reason, for the inputs in
 * {@code failure-reason/inputs.json} — the answers the Rust agent's scrub is held to.
 *
 * <p>The scrub is a chain of regular expressions, and two engines disagree at exactly the places these
 * inputs sit on: what {@code \s}, {@code \b} and {@code (?i)} admit beyond ASCII, where a lazy match
 * stops, how a length is counted. A reason that leaves the Rust agent with a secret this side would
 * have masked reaches the control plane's screen and the agent's log.
 *
 * <p>A text in {@code inputs.json} is a string, or an array of fragments read joined: the invented key
 * blocks are cut inside their armour, because written whole, gitleaks reads two of them a few lines apart
 * as one private key (it decodes JSON escapes, so an escaped space does not hide it).
 */
class FailureReasonReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void theAnswersTheRustScrubIsHeldTo() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("failure-reason/inputs.json"));
        ArrayNode answers = JSON.createArrayNode();
        for (JsonNode input : inputs) {
            List<String> secrets = new ArrayList<>();
            input.path("secrets").forEach(secret -> secrets.add(secret.isNull() ? null : text(secret)));
            answers.addObject()
                    .put("name", input.path("name").asText())
                    .put("scrubbed", FailureReason.scrub(text(input.path("raw")), secrets));
        }
        ReferenceSet.expect("failure-reason/java-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    /** A string, or the fragments of an array joined. */
    private static String text(JsonNode node) {
        if (!node.isArray()) {
            return node.asText();
        }
        StringBuilder joined = new StringBuilder();
        node.forEach(fragment -> joined.append(fragment.asText()));
        return joined.toString();
    }
}
