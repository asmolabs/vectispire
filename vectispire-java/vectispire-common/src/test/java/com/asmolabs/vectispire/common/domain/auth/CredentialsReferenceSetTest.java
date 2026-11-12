package com.asmolabs.vectispire.common.domain.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeys;
import com.asmolabs.vectispire.common.domain.apikeys.InvalidApiKeyException;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * What the session and key rules answer for the inputs in {@code credentials/inputs.json} — the answers the Rust
 * control plane's credentials are held to (plan, Phase 1, task 1.2).
 *
 * <p><b>Sessions must survive the switch.</b> A session is found by the SHA-256 of its token, an API key by its
 * prefix and an Argon2id PHC string: a hash computed differently, a header read differently or a PHC piece parsed
 * differently is a signed-in user signed out, or a pipeline's key refused, on the day the control plane changes
 * language. Each of those is a line here.
 *
 * <p><b>Two files, because a hash is salted.</b> {@code java-minted.json} holds PHC strings this side made, and the
 * variants of them a reader must refuse or accept; it is written once, in write mode, and only checked to still
 * verify afterwards — a fresh salt would rewrite it on every run. {@code java-answers.json} holds every
 * deterministic answer, the verdicts on those strings included, and is compared byte for byte like every reference
 * set.
 */
class CredentialsReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void theAnswersTheRustCredentialsAreHeldTo() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("credentials/inputs.json"));
        List<String> secrets = new ArrayList<>();
        inputs.path("secrets").forEach(secret -> secrets.add(secret.asText()));

        JsonNode minted = minted(inputs, secrets);

        ObjectNode answers = JSON.createObjectNode();

        ArrayNode tokens = answers.putArray("tokenHashes");
        for (JsonNode token : inputs.path("tokens")) {
            tokens.addObject()
                    .put("token", token.asText())
                    .put("hash", Sessions.hashOf(token.asText()))
                    .put("handoffHash", Sessions.handoffHashOf(token.asText()));
        }

        ArrayNode bearer = answers.putArray("bearer");
        for (JsonNode header : inputs.path("headers")) {
            String value = header.isNull() ? null : header.asText();
            ObjectNode answer = bearer.addObject();
            answer.put("header", value);
            answer.put("token", Sessions.bearerToken(value).orElse(null));
        }

        ArrayNode states = answers.putArray("states");
        for (JsonNode state : inputs.path("states")) {
            Sessions.Policy policy = new Sessions.Policy(
                    Duration.parse(state.path("absolute").asText()), Duration.parse(state.path("idle").asText()));
            Instant created = Instant.parse(state.path("createdAt").asText());
            Instant lastSeen = Instant.parse(state.path("lastSeenAt").asText());
            Instant now = Instant.parse(state.path("now").asText());
            states.addObject()
                    .put("name", state.path("name").asText())
                    .put("state", Sessions.stateOf(created, lastSeen, now, policy).name())
                    .put("recordActivity", Sessions.shouldRecordActivity(lastSeen, now, policy));
        }

        ArrayNode scopeLists = answers.putArray("scopeLists");
        for (JsonNode list : inputs.path("scopeLists")) {
            List<String> requested = null;
            if (!list.isNull()) {
                requested = new ArrayList<>();
                for (JsonNode scope : list) {
                    requested.add(scope.isNull() ? null : scope.asText());
                }
            }
            ObjectNode answer = scopeLists.addObject();
            answer.set("input", list);
            try {
                ArrayNode granted = answer.putArray("scopes");
                ApiKeys.normalizeScopes(requested).forEach(scope -> granted.add(scope.wireName()));
            } catch (InvalidApiKeyException refused) {
                answer.remove("scopes");
                answer.put("error", refused.getMessage());
            }
        }

        ArrayNode lifetimes = answers.putArray("lifetimes");
        for (JsonNode lifetime : inputs.path("lifetimes")) {
            Integer days = lifetime.isNull() ? null : lifetime.asInt();
            ObjectNode answer = lifetimes.addObject();
            answer.set("input", lifetime);
            try {
                answer.put("days", ApiKeys.normalizeLifetime(days).map(period -> period.getDays()).orElse(null));
            } catch (InvalidApiKeyException refused) {
                answer.remove("days");
                answer.put("error", refused.getMessage());
            }
        }

        ArrayNode wireNames = answers.putArray("wireNames");
        for (JsonNode name : inputs.path("wireNames")) {
            wireNames.addObject()
                    .put("input", name.asText())
                    .put("scope", ApiKeyScope.fromWireName(name.asText()).map(ApiKeyScope::wireName).orElse(null));
        }

        ArrayNode verify = answers.putArray("verify");
        ArrayNode rehash = answers.putArray("needsRehash");
        for (JsonNode encoded : minted.path("encoded")) {
            String name = encoded.path("name").asText();
            String value = encoded.path("value").isNull() ? null : encoded.path("value").asText();
            for (int secret = 0; secret < secrets.size(); secret++) {
                verify.addObject()
                        .put("encoded", name)
                        .put("secret", secret)
                        .put("matches", PasswordHasher.verify(secrets.get(secret), value));
            }
            rehash.addObject().put("encoded", name).put("needs", PasswordHasher.needsRehash(value));
        }

        ReferenceSet.expect("credentials/java-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    /**
     * The PHC strings: made here in write mode, read back otherwise — and in either mode each base string must still
     * verify its own secret, so a file that no longer does is red here first.
     */
    private static JsonNode minted(JsonNode inputs, List<String> secrets) throws Exception {
        if (Boolean.getBoolean("vectispire.rust.reference.write")) {
            ObjectNode file = JSON.createObjectNode();
            ArrayNode encoded = file.putArray("encoded");
            for (JsonNode derived : inputs.path("derived")) {
                String secret = secrets.get(derived.path("secret").asInt());
                String hash = PasswordHasher.hash(
                        secret, derived.path("m").asInt(), derived.path("t").asInt(), derived.path("p").asInt());
                String name = derived.path("name").asText();
                encoded.addObject().put("name", name).put("value", hash).put("base", derived.path("secret").asInt());
                for (String[] variant : variants(hash)) {
                    encoded.addObject().put("name", name + " / " + variant[0]).put("value", variant[1]);
                }
            }
            encoded.addObject().put("name", "null").putNull("value");
            encoded.addObject().put("name", "empty").put("value", "");
            encoded.addObject().put("name", "blank").put("value", " \t");
            encoded.addObject().put("name", "bcrypt").put("value", "$2a$10$inventedinventedinventeduinventedinventedinventedinve");
            encoded.addObject().put("name", "no pieces").put("value", "argon2id");
            ReferenceSet.expect("credentials/java-minted.json", JSON.writeValueAsString(file) + "\n");
        }
        JsonNode file = JSON.readTree(ReferenceSet.read("credentials/java-minted.json"));
        for (JsonNode encoded : file.path("encoded")) {
            if (encoded.has("base")) {
                assertThat(PasswordHasher.verify(secrets.get(encoded.path("base").asInt()), encoded.path("value").asText()))
                        .as("%s still verifies its secret", encoded.path("name").asText())
                        .isTrue();
            }
        }
        return file;
    }

    /** The ways a stored string can differ from what {@code hash} wrote, each a verdict the reader must agree on. */
    private static List<String[]> variants(String hash) {
        String[] parts = hash.split("\\$");
        // ["", "argon2id", "v=19", "m=…,t=…,p=…", salt, digest]
        String parameters = parts[3];
        String[] each = parameters.split(",");
        String reordered = each[2] + "," + each[1] + "," + each[0];
        String digest = parts[5];
        char first = digest.charAt(0);
        String flipped = (first == 'A' ? 'B' : 'A') + digest.substring(1);
        List<String[]> variants = new ArrayList<>();
        variants.add(new String[] {"trailing separator", hash + "$"});
        variants.add(new String[] {"two trailing separators", hash + "$$"});
        variants.add(new String[] {"extra piece", hash + "$extra"});
        variants.add(new String[] {"reordered parameters", String.join("$", parts[0], parts[1], parts[2], reordered, parts[4], parts[5])});
        variants.add(new String[] {"padded salt", String.join("$", parts[0], parts[1], parts[2], parameters, parts[4] + "==", parts[5])});
        variants.add(new String[] {"version 16", String.join("$", parts[0], parts[1], "v=16", parameters, parts[4], parts[5])});
        variants.add(new String[] {"no version", String.join("$", parts[0], parts[1], "x", parameters, parts[4], parts[5])});
        variants.add(new String[] {"argon2i", String.join("$", parts[0], "argon2i", parts[2], parameters, parts[4], parts[5])});
        variants.add(new String[] {"Argon2id", String.join("$", parts[0], "Argon2id", parts[2], parameters, parts[4], parts[5])});
        variants.add(new String[] {"flipped digest", String.join("$", parts[0], parts[1], parts[2], parameters, parts[4], flipped)});
        variants.add(new String[] {"short digest", String.join("$", parts[0], parts[1], parts[2], parameters, parts[4], digest.substring(0, 40))});
        variants.add(new String[] {"no memory", String.join("$", parts[0], parts[1], parts[2], each[1] + "," + each[2], parts[4], parts[5])});
        variants.add(new String[] {"plus sign", String.join("$", parts[0], parts[1], parts[2], each[0].replace("=", "=+") + "," + each[1] + "," + each[2], parts[4], parts[5])});
        variants.add(new String[] {"salt not base64", String.join("$", parts[0], parts[1], parts[2], parameters, "*" + parts[4].substring(1), parts[5])});
        variants.add(new String[] {"five pieces", String.join("$", parts[0], parts[1], parts[2], parameters, parts[4])});
        return variants;
    }
}
