package com.asmolabs.vectispire.core.golden;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The recorder's masking of what is random, on the part a replay reads before anything else: the request's route.
 * A path is written with the characters base64 is, and one with a digit, a capital and a word looked like a random
 * key: the whole path became {@code «secret:N»} and its recording matched no route of the contract.
 */
class PlaceholdersTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private static String rendered(String json) throws Exception {
        JsonNode record = MAPPER.readTree(json);
        Placeholders placeholders = new Placeholders();
        placeholders.collect(record, null);
        return placeholders.render(record).path("request").path("path").asText();
    }

    @Test
    @DisplayName("a long path with a digit, a capital and a word is a route, not a secret")
    void aPathIsNotMaskedWhole() throws Exception {
        String shown = rendered("{\"request\":{\"method\":\"PUT\",\"path\":\"/api/v1/projects/1/checklists/contacts/ArchitectureOwnerProfile\"}}");
        assertThat(shown).isEqualTo("/api/v1/projects/1/checklists/contacts/ArchitectureOwnerProfile");
    }

    @Test
    @DisplayName("a path keeps its words whether or not an identity in it is numbered")
    void theWordsOfAPathSurvive() throws Exception {
        String shown = rendered("{\"request\":{\"method\":\"GET\",\"path\":\"/api/v1/projects/123456789/checklists/contacts/PO\"}}");
        assertThat(shown).startsWith("/api/v1/projects/").endsWith("/checklists/contacts/PO");
    }

    @Test
    @DisplayName("a token that is one segment of a path is still masked")
    void aTokenSegmentIsStillMasked() throws Exception {
        // Invented: 43 characters of base64url with a capital, a lower-case letter and a digit — what RANDOM_TOKEN
        // reads as a random token. Not a credential; the marker is how gitleaks is told so.
        String token = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5kL7nP9r"; // gitleaks:allow
        assertThat(token).hasSize(43);
        String shown = rendered("{\"request\":{\"method\":\"GET\",\"path\":\"/api/v1/scorecards/badges/" + token + ".svg\"}}");
        assertThat(shown).startsWith("/api/v1/scorecards/badges/").endsWith(".svg").doesNotContain(token);
    }

    @Test
    @DisplayName("a padded key without a digit is still masked in the row it is stored in")
    void aPaddedKeyWithoutADigitIsMasked() throws Exception {
        // Invented: base64 of 32 bytes, an Ed25519 public key's shape, with no digit — one generated key in about
        // 1,300 is. It stayed literal in t_agent.signing_public_key, the replay's own key could not match it, and
        // rust-replay went red on a run that drew one.
        String key = "QwErTyUiOpAsDfGhJkLzXcVbNm+wErTyUiOpAsDfGhJ="; // gitleaks:allow
        JsonNode record = MAPPER.readTree("{\"effect\":{\"t_agent\":{\"updated\":[{\"changed\":"
                + "{\"signing_public_key\":{\"from\":null,\"to\":\"" + key + "\"}}}]}}}");
        Placeholders placeholders = new Placeholders();
        placeholders.collect(record, null);
        String shown = placeholders.render(record)
                .at("/effect/t_agent/updated/0/changed/signing_public_key/to").asText();
        assertThat(shown).matches("«secret:\\d+»");
    }
}
