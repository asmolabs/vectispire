package com.asmolabs.vectispire.common.domain.auth;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

/**
 * What the second factor and the sign-in throttle answer for the inputs in {@code sign-in/inputs.json} — the
 * answers the Rust control plane's sign-in is held to (MIGRATION.md, Phase 1, task 1.3).
 *
 * <p><b>An enrolled authenticator must survive the switch.</b> A TOTP secret is stored as Base32 and read back on
 * every sign-in: a letter decoded differently, a step counted differently around the epoch, or a code compared after
 * a different trim is a second factor that stops working on the day the control plane changes language. The
 * throttle's keys are rows in {@code t_login_attempt}: a username folded differently starts a fresh budget for
 * every spelling the database's collation treats as one, which is the oracle {@link LoginThrottle#userKey} closes.
 *
 * <p>A code is not an input but an answer: {@code codeAt} asks this side for the code of a shifted instant, and the
 * answer carries the code that was submitted, so that the Rust side checks the same string without computing it.
 */
class SignInReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    private static final HexFormat HEX = HexFormat.of();

    @Test
    void theAnswersTheRustSignInIsHeldTo() throws Exception {
        JsonNode inputs = JSON.readTree(ReferenceSet.read("sign-in/inputs.json"));
        ObjectNode answers = JSON.createObjectNode();

        ArrayNode encoded = answers.putArray("base32Encode");
        for (JsonNode hex : inputs.path("base32Encode")) {
            encoded.addObject()
                    .put("hex", hex.asText())
                    .put("base32", Totp.encodeBase32(HEX.parseHex(hex.asText())));
        }

        ArrayNode decoded = answers.putArray("base32Decode");
        for (JsonNode text : inputs.path("base32Decode")) {
            decoded.addObject()
                    .put("base32", text.asText())
                    .put("hex", HEX.formatHex(Totp.decodeBase32(text.asText())));
        }

        ArrayNode codes = answers.putArray("codes");
        for (JsonNode entry : inputs.path("codes")) {
            String secret = entry.path("secret").asText();
            Instant instant = Instant.parse(entry.path("instant").asText());
            codes.addObject()
                    .put("secret", secret)
                    .put("instant", instant.toString())
                    .put("code", Totp.generateCode(secret, instant));
        }

        ArrayNode matches = answers.putArray("matches");
        for (JsonNode entry : inputs.path("matches")) {
            String secret = text(entry.path("secret"));
            Instant instant = Instant.parse(entry.path("instant").asText());
            String code = entry.has("codeAt")
                    ? entry.path("format").asText().replace("%s",
                            Totp.generateCode(secret, instant.plusSeconds(entry.path("codeAt").asLong())))
                    : text(entry.path("code"));
            OptionalLong step = Totp.matchingStep(secret, code, instant);
            ObjectNode answer = matches.addObject();
            answer.put("secret", secret);
            answer.put("code", code);
            answer.put("instant", instant.toString());
            if (step.isPresent()) {
                answer.put("step", step.getAsLong());
            } else {
                answer.putNull("step");
            }
        }

        ArrayNode uris = answers.putArray("uris");
        for (JsonNode entry : inputs.path("uris")) {
            String username = entry.path("username").asText();
            String issuer = entry.path("issuer").asText();
            uris.addObject()
                    .put("username", username)
                    .put("issuer", issuer)
                    .put("uri", Totp.qrCodeUri(username, "JBSWY3DPEHPK3PXP", issuer));
        }

        ArrayNode userKeys = answers.putArray("userKeys");
        for (JsonNode username : inputs.path("userKeys")) {
            userKeys.addObject()
                    .put("username", username.asText())
                    .put("key", LoginThrottle.userKey(username.asText()));
        }

        ArrayNode addresses = answers.putArray("addresses");
        for (JsonNode address : inputs.path("addresses")) {
            String value = text(address);
            ObjectNode answer = addresses.addObject();
            answer.put("address", value);
            answer.put("bucket", ClientBuckets.of(value));
            answer.put("clientKey", LoginThrottle.clientKey(value));
        }

        ArrayNode throttle = answers.putArray("throttle");
        for (JsonNode entry : inputs.path("throttle")) {
            Instant now = Instant.parse(entry.path("now").asText());
            LoginThrottle.Decision decision = LoginThrottle.decide(
                    new LoginThrottle.Attempts(instants(entry.path("user")), instants(entry.path("client"))), now);
            decision(throttle.addObject().put("name", entry.path("name").asText()), decision);
        }

        ArrayNode throttleOne = answers.putArray("throttleOne");
        for (JsonNode entry : inputs.path("throttleOne")) {
            Instant now = Instant.parse(entry.path("now").asText());
            LoginThrottle.Decision decision =
                    LoginThrottle.decide(instants(entry.path("attempts")), entry.path("limit").asInt(), now);
            decision(throttleOne.addObject().put("name", entry.path("name").asText()), decision);
        }

        answers.put("accountKey", LoginThrottle.accountKey(42));
        answers.put("secondFactorKey", LoginThrottle.secondFactorKey(42));

        ReferenceSet.expect("sign-in/java-answers.json", JSON.writeValueAsString(answers) + "\n");
    }

    private static void decision(ObjectNode answer, LoginThrottle.Decision decision) {
        Duration wait = decision.retryAfter();
        answer.put("allowed", decision.allowed());
        answer.put("retryAfterSeconds", wait.getSeconds());
        answer.put("retryAfterNanos", wait.getNano());
    }

    private static List<Instant> instants(JsonNode array) {
        List<Instant> instants = new ArrayList<>();
        array.forEach(instant -> instants.add(Instant.parse(instant.asText())));
        return instants;
    }

    private static String text(JsonNode node) {
        return node.isNull() || node.isMissingNode() ? null : node.asText();
    }
}
