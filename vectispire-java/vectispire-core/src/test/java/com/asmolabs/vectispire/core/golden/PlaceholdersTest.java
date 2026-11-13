package com.asmolabs.vectispire.core.golden;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import com.asmolabs.vectispire.common.domain.crypto.SealingKeyAttestation;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.nio.charset.StandardCharsets;
import java.util.List;
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

    @Test
    @DisplayName("a certificate stays literal, its body untouched, and a key is still a placeholder")
    void aCertificateIsKeptAndAKeyIsNot() throws Exception {
        // Invented bodies, not real material: what matters is that a base64 run with a digit and both cases inside a
        // certificate is not read as a token, and that a key's block is hidden whole.
        String certificate = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBkxhcHNlZA==\n-----END CERTIFICATE-----";
        String key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIKnzQ7mZ9x2Wb8yT4uR1sV3pL6dE0fG5hJ7kM2nC9aB4\n-----END PRIVATE KEY-----"; // gitleaks:allow
        JsonNode record = MAPPER.readTree("{\"request\":{\"method\":\"PUT\",\"path\":\"/api/v1/siem/config\",\"body\":"
                + "{\"tlsCaPem\":" + MAPPER.writeValueAsString(certificate) + ",\"key\":" + MAPPER.writeValueAsString(key) + "}}}");
        Placeholders placeholders = new Placeholders();
        placeholders.collect(record, null);
        JsonNode body = placeholders.render(record).at("/request/body");
        assertThat(body.path("tlsCaPem").asText()).isEqualTo(certificate);
        assertThat(body.path("key").asText()).isEqualTo("«pem:private-key:1»");
    }

    @Test
    @DisplayName("a sealing-key signature by a seed the test showed, for an agent it named, over a fixture key, is the computation the replay repeats")
    void aSealingSignatureIsWrittenAsItsComputation() throws Exception {
        // As AgentSealingKeyRoutesTest: the server draws the agent's id and the pinned seed, the agent signs a fixture
        // key with it. The value is Java's agent's, which the replay's is not: only the computation can be replayed.
        java.util.UUID agent = java.util.UUID.randomUUID();
        String seed = com.asmolabs.vectispire.common.domain.crypto.ResultAttestation.generate().privateKey();
        String stranger = com.asmolabs.vectispire.common.domain.crypto.ResultAttestation.generate().privateKey();
        String key = FixtureSealingKeys.pair(1).publicKey();
        String unfixed = new com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope().generateKeyPair().publicKey();
        Placeholders placeholders = new Placeholders();
        JsonNode pinned = MAPPER.readTree("{\"response\":{\"status\":200,\"body\":{\"json\":{\"id\":\"" + agent
                + "\",\"privateKey\":\"" + seed + "\"}}}}");
        placeholders.collect(pinned, null);
        placeholders.render(pinned);

        JsonNode signed = announcement(key, SealingKeyAttestation.sign(seed, agent, 1_000L, key));
        placeholders.collect(signed, null);
        JsonNode shown = placeholders.render(signed).at("/request/body/json");
        assertThat(shown.path("signature").asText()).isEqualTo("«sealing-signature:v2:secret:1:uuid:1:1000:" + key + "»");
        assertThat(shown.path("public_key").asText()).isEqualTo(key);

        // Signed by a key the test kept to itself, or over a key that is not a fixture: a secret, as before.
        for (JsonNode other : List.of(
                announcement(key, SealingKeyAttestation.sign(stranger, agent, 1_000L, key)),
                announcement(unfixed, SealingKeyAttestation.sign(seed, agent, 1_000L, unfixed)))) {
            placeholders.collect(other, null);
            assertThat(placeholders.render(other).at("/request/body/json/signature").asText()).matches("«secret:\\d+»");
        }
    }

    private static JsonNode announcement(String key, String signature) throws Exception {
        return MAPPER.readTree("{\"request\":{\"method\":\"POST\",\"path\":\"/api/v1/agent/sealing-key\",\"body\":{\"json\":"
                + "{\"generation\":1000,\"public_key\":\"" + key + "\",\"signature\":\"" + signature + "\"}}}}");
    }

    @Test
    @DisplayName("one character repeated under a credential's name is padding, kept with its length; a short token is still hidden")
    void paddingIsNoSecret() throws Exception {
        String padding = "t".repeat(8_193);
        JsonNode record = MAPPER.readTree("{\"request\":{\"method\":\"POST\",\"path\":\"/api/v1/git-tokens\",\"body\":{\"json\":"
                + "{\"token\":\"" + padding + "\",\"other\":{\"token\":\"ghp_abc\"},\"two\":{\"token\":\"abaabbab\"}}}}}");
        Placeholders placeholders = new Placeholders();
        placeholders.collect(record, null);
        JsonNode body = placeholders.render(record).at("/request/body/json");
        assertThat(body.path("token").asText()).isEqualTo(padding);
        assertThat(body.at("/other/token").asText()).matches("«secret:\\d+»");
        // One character, not few: two make a value someone may have chosen.
        assertThat(body.at("/two/token").asText()).matches("«secret:\\d+»");
    }

    @Test
    @DisplayName("a repository's identity guard is a public digest, kept; another digest is still numbered")
    void anIdentityGuardIsKept() throws Exception {
        String identity = "gitlab.example.org/team/legacy";
        String guard = com.asmolabs.vectispire.common.domain.crypto.Digests.sha256Fields(identity, "main", "");
        // A repository named after the clock: its identity is a placeholder, and so must its guard be.
        String timed = "example.invalid/team/service-123456789012345";
        String timedGuard = com.asmolabs.vectispire.common.domain.crypto.Digests.sha256Fields(timed, "main", "");
        JsonNode record = MAPPER.readTree("{\"effect\":{\"t_repository\":{\"updated\":["
                + "{\"key\":{\"id\":1},\"changed\":{\"url_identity\":{\"from\":null,\"to\":\"" + identity + "\"},"
                + "\"identity_guard\":{\"from\":null,\"to\":\"" + guard + "\"},\"other_digest\":{\"from\":null,\"to\":\"" + guard + "\"}}},"
                + "{\"key\":{\"id\":2},\"changed\":{\"url_identity\":{\"from\":null,\"to\":\"" + timed + "\"},"
                + "\"identity_guard\":{\"from\":null,\"to\":\"" + timedGuard + "\"}}},"
                + "{\"key\":{\"id\":3},\"changed\":{\"identity_guard\":{\"from\":null,\"to\":\"" + timedGuard.replace('a', 'b') + "\"}}}]}}}");
        Placeholders placeholders = new Placeholders();
        placeholders.collect(record, null);
        JsonNode updated = placeholders.render(record).at("/effect/t_repository/updated");
        assertThat(updated.at("/0/changed/identity_guard/to").asText()).isEqualTo(guard);
        assertThat(updated.at("/0/changed/other_digest/to").asText()).as("another column").matches("«sha256:\\d+»");
        assertThat(updated.at("/1/changed/identity_guard/to").asText()).matches("«sha256:\\d+»");
        // A guard whose row shows no identity is a digest like any other.
        assertThat(updated.at("/2/changed/identity_guard/to").asText()).matches("«sha256:\\d+»");
    }

    @Test
    @DisplayName("an invented fixture key stays literal, by fingerprint; a key one character away does not")
    void aFixtureKeyIsKeptAndNoOtherKey() throws Exception {
        // Hidden, the fixture left POST /api/v1/ssh-keys and the SIEM's refused paste with nothing to send: 23
        // recordings deferred. The rule is the exact block, never its label or its shape.
        String fixture = FixturePrivateKeys.PASTED_FOR_A_CA;
        String near = fixture.replace("QQg", "QQh");
        JsonNode record = MAPPER.readTree("{\"request\":{\"method\":\"PUT\",\"path\":\"/api/v1/siem/config\",\"body\":{\"json\":"
                + "{\"tlsCaPem\":" + MAPPER.writeValueAsString(fixture) + ",\"other\":" + MAPPER.writeValueAsString(near)
                + ",\"ssh\":" + MAPPER.writeValueAsString(FixturePrivateKeys.FORGE_IMPORT + "A".repeat(40)) + "}}}}");
        Placeholders placeholders = new Placeholders();
        placeholders.collect(record, null);
        JsonNode body = placeholders.render(record).at("/request/body/json");

        assertThat(body.path("tlsCaPem").asText()).isEqualTo(fixture);
        assertThat(body.path("other").asText()).isEqualTo("«pem:private-key:1»");
        // A fixture followed by padding, as IntegrationInputBoundsTest sends past the ceiling: the block is kept.
        assertThat(body.path("ssh").asText()).isEqualTo(FixturePrivateKeys.FORGE_IMPORT + "A".repeat(40));
    }

    @Test
    @DisplayName("a signature the test sends and the public key it sends beside it are kept; the server's signature and a private key are not")
    void aSignatureSentAndAPublicKeyAreKept() throws Exception {
        // Generated here, as CryptoRoutesTest does: hidden, the replay could send no signature that verifies, and
        // /api/v1/crypto/verify was deferred for it (the forger's key, the context's signature).
        java.security.KeyPair forger = CosignSigner.generateKeyPair();
        String signature = CosignSigner.sign("{}".getBytes(StandardCharsets.UTF_8), forger.getPrivate());
        String publicKey = CosignSigner.toPem(forger.getPublic());
        String privateKey = CosignSigner.toPem(forger.getPrivate());
        String answered = CosignSigner.sign("{\"a\":1}".getBytes(StandardCharsets.UTF_8), forger.getPrivate());
        // As CryptoRoutesTest's first request: a text body, read by its shape alone.
        String sent = "{\n  \"payload\": \"{}\",\n  \"signature\": \"" + signature + "\"\n}\n";
        JsonNode record = MAPPER.readTree("{\"request\":{\"method\":\"POST\",\"path\":\"/api/v1/crypto/verify\",\"body\":{"
                + "\"text\":" + MAPPER.writeValueAsString(sent) + ",\"json\":{\"publicKey\":" + MAPPER.writeValueAsString(publicKey)
                + ",\"key\":" + MAPPER.writeValueAsString(privateKey) + "}}},"
                + "\"response\":{\"status\":200,\"body\":{\"json\":{\"signature\":\"" + answered + "\"}}}}");
        Placeholders placeholders = new Placeholders();
        placeholders.collect(record, null);
        JsonNode shown = placeholders.render(record);

        assertThat(shown.at("/request/body/text").asText()).isEqualTo(sent);
        assertThat(shown.at("/request/body/json/publicKey").asText()).isEqualTo(publicKey);
        assertThat(shown.at("/request/body/json/key").asText()).isEqualTo("«pem:private-key:1»\n");
        // Java's k is random where Rust's is not: a signature the server makes matches only as a placeholder.
        assertThat(shown.at("/response/body/json/signature").asText()).matches("«secret:\\d+»");
    }

    @Test
    @DisplayName("only an ECDSA signature's DER reads as one: a random key of the same length does not")
    void onlyASignatureReadsAsOne() {
        java.security.KeyPair pair = CosignSigner.generateKeyPair();
        String signature = CosignSigner.sign(new byte[] {1}, pair.getPrivate());
        assertThat(Placeholders.isEcdsaSignature(signature)).isTrue();
        byte[] der = java.util.Base64.getDecoder().decode(signature);
        byte[] anotherTag = der.clone();
        anotherTag[0] = 0x31; // a SET, its lengths all agreeing
        assertThat(Placeholders.isEcdsaSignature(java.util.Base64.getEncoder().encodeToString(anotherTag))).isFalse();
        byte[] shortS = der.clone();
        shortS[5 + der[3]]--; // s one byte shorter than what follows it
        assertThat(Placeholders.isEcdsaSignature(java.util.Base64.getEncoder().encodeToString(shortS))).isFalse();
        byte[] random = new byte[72];
        new java.security.SecureRandom().nextBytes(random);
        random[0] = 0x30; // a SEQUENCE's tag, its lengths still random
        assertThat(Placeholders.isEcdsaSignature(java.util.Base64.getEncoder().encodeToString(random))).isFalse();
        assertThat(Placeholders.isEcdsaSignature(java.util.Base64.getEncoder()
                .encodeToString(pair.getPublic().getEncoded()))).isFalse();
    }
}
