package com.asmolabs.vectispire.common.domain.teams;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/**
 * What {@link TeamRules} answers for the inputs in {@code teams/inputs.json} — the answers the Rust control plane's
 * teams and SCIM groups are held to (MIGRATION.md, Phase 1, task 1.7).
 *
 * <p>A team's name is unique and keyed on, a target kind decides what a grant opens: a trim that keeps a character
 * Java removes, or a kind lower-cased under another rule, is a second team the screen cannot tell apart, or a grant
 * stored here and refused there. Lengths are UTF-16 units, so the inputs straddle the limits with emoji.
 */
class TeamRulesReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void theAnswersTheRustTeamsAreHeldTo() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("teams/inputs.json"));
        ObjectNode answers = JSON.createObjectNode();

        answer(answers.putArray("names"), inputs.path("names"), TeamRules::validateName);
        answer(answers.putArray("descriptions"), inputs.path("descriptions"), TeamRules::trimDescription);
        answer(answers.putArray("kinds"), inputs.path("kinds"), TeamRules::validateTargetKind);

        ReferenceSet.expect("teams/java-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    /** One line per input: what the rule returned, or the sentence it refused with. */
    private static void answer(ArrayNode answers, JsonNode inputs, UnaryOperator<String> rule) {
        for (JsonNode input : inputs) {
            String value = input.isNull() ? null : input.asText();
            ObjectNode answer = answers.addObject();
            answer.put("input", value);
            try {
                answer.put("value", rule.apply(value));
            } catch (InvalidInputException refused) {
                answer.put("error", refused.getMessage());
            }
        }
    }
}
