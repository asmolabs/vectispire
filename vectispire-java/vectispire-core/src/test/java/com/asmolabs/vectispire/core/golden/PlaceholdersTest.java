package com.asmolabs.vectispire.core.golden;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.crypto.CosignSigner;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.nio.charset.StandardCharsets;
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
