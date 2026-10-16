package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.Test;

/**
 * The agent's cryptography, both ways across the two implementations (see {@code ReferenceSet}).
 *
 * <p><b>The two real directions.</b> The agent signs its results, its failure reports and its sealing
 * key, and the control plane verifies them; the control plane seals deployment keys and tokens to the
 * agent's sealing key, and the agent opens them. So this side writes signatures and envelopes for the
 * Rust agent to reproduce and open ({@code crypto/java-vectors.json}), and verifies what the Rust agent
 * signed and announced ({@code crypto/rust-vectors.json}) — sealing to the Rust agent's own key.
 *
 * <p><b>No key is written down.</b> Every private key is the SHA-256 of a label both sides spell the
 * same, so the files hold public keys, signatures and envelopes only, and nothing secret-shaped.
 * Ed25519 is deterministic: the Rust signature of the same message must be the same bytes, not merely
 * a valid one. The envelopes' randomness is a stream derived from a label too, so regenerating the file
 * changes nothing unless the code did.
 */
class CryptoReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    static final String SIGNING_SEED_LABEL = "vectispire-rust-reference:result-signing-seed";
    static final String JAVA_SEALING_LABEL = "vectispire-rust-reference:java-sealing-key";
    static final UUID AGENT_ID = UUID.fromString("3f2b6c1e-8d4a-4b7e-9c2f-5a1d0e7b9c34");
    static final long GENERATION = 3;
    static final long SCAN_ID = 42;

    static byte[] labelled(String label) {
        return Digests.sha256(label.getBytes(StandardCharsets.UTF_8));
    }

    /** SHA-256(label ‖ counter) blocks: deterministic, and only ever randomness for a test. */
    static final class LabelledRandom extends SecureRandom {
        private final String label;
        private long counter;

        LabelledRandom(String label) {
            this.label = label;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            int filled = 0;
            while (filled < bytes.length) {
                byte[] block = Digests.sha256((label + ":" + counter++).getBytes(StandardCharsets.UTF_8));
                int count = Math.min(block.length, bytes.length - filled);
                System.arraycopy(block, 0, bytes, filled, count);
                filled += count;
            }
        }
    }

    static String spki(X25519PrivateKeyParameters key) throws Exception {
        return Base64.getEncoder().encodeToString(
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key.generatePublicKey()).getEncoded());
    }

    @Test
    void theVectorsTheRustAgentReproducesAndOpens() throws Exception {
        String seed = Base64.getEncoder().encodeToString(labelled(SIGNING_SEED_LABEL));
        String signingPublic = Base64.getEncoder().encodeToString(
                new Ed25519PrivateKeyParameters(labelled(SIGNING_SEED_LABEL), 0).generatePublicKey().getEncoded());
        X25519PrivateKeyParameters javaSealing = new X25519PrivateKeyParameters(labelled(JAVA_SEALING_LABEL), 0);
        String javaSealingPublic = spki(javaSealing);
        String resultBody = "{\"secrets\":[{\"rule\":\"generic-api-key\",\"file\":\"src/app.env\",\"line\":3}]}";
        String failureBody = "{\"kind\":\"TRANSIENT\",\"message\":\"The clone of https://gitlab.example.org/x timed out.\"}";

        ObjectNode vectors = JSON.createObjectNode();
        vectors.put("signing_seed_label", SIGNING_SEED_LABEL);
        vectors.put("signing_public", signingPublic);
        vectors.put("scan_id", SCAN_ID);
        vectors.put("result_body", resultBody);
        vectors.put("result_signature", ResultAttestation.sign(seed, SCAN_ID, resultBody.getBytes(StandardCharsets.UTF_8)));
        vectors.put("failure_body", failureBody);
        vectors.put("failure_signature",
                ResultAttestation.signFailure(seed, SCAN_ID, failureBody.getBytes(StandardCharsets.UTF_8)));
        vectors.put("agent_id", AGENT_ID.toString());
        vectors.put("generation", GENERATION);
        vectors.put("java_sealing_label", JAVA_SEALING_LABEL);
        vectors.put("java_sealing_public", javaSealingPublic);
        vectors.put("java_sealing_attestation", SealingKeyAttestation.sign(seed, AGENT_ID, GENERATION, javaSealingPublic));

        // Sealed to the Rust agent's announced key, read from its own vectors.
        JsonNode rust = JSON.readTree(ReferenceSet.read("crypto/rust-vectors.json"));
        String rustSealingPublic = rust.path("sealing_public").asText();
        assertThat(SealedEnvelope.isUsablePublicKey(rustSealingPublic))
                .as("the Rust agent's sealing key is an X25519 key in the encoding this side reads").isTrue();
        ArrayNode envelopes = vectors.putArray("envelopes_to_rust");
        SealedEnvelope sealer = new SealedEnvelope(new LabelledRandom("vectispire-rust-reference:envelope"));
        for (SealedEnvelope.Context context : new SealedEnvelope.Context[] {
                SealedEnvelope.Context.deploymentKey(),
                SealedEnvelope.Context.httpsToken("gitlab.example.org", "x-access-token"),
                SealedEnvelope.Context.httpsToken("gitlab.example.org", null)}) {
            String plain = "invented material for " + context.value();
            ObjectNode envelope = envelopes.addObject();
            envelope.put("context", context.value());
            envelope.put("plain", plain);
            envelope.put("sealed", sealer.seal(rustSealingPublic, plain, context));
        }
        ReferenceSet.expect("crypto/java-vectors.json", JSON.writeValueAsString(vectors) + "\n");
    }

    @Test
    void whatTheRustAgentSignedVerifiesHere() throws Exception {
        JsonNode rust = JSON.readTree(ReferenceSet.read("crypto/rust-vectors.json"));
        String signingPublic = Base64.getEncoder().encodeToString(
                new Ed25519PrivateKeyParameters(labelled(SIGNING_SEED_LABEL), 0).generatePublicKey().getEncoded());
        long scanId = rust.path("scan_id").asLong();
        assertThat(ResultAttestation.verify(signingPublic, scanId,
                rust.path("result_body").asText().getBytes(StandardCharsets.UTF_8), rust.path("result_signature").asText()))
                .as("a result the Rust agent signed").isTrue();
        assertThat(ResultAttestation.verifyFailure(signingPublic, scanId,
                rust.path("failure_body").asText().getBytes(StandardCharsets.UTF_8), rust.path("failure_signature").asText()))
                .as("a failure report the Rust agent signed").isTrue();
        assertThat(ResultAttestation.verify(signingPublic, scanId,
                rust.path("failure_body").asText().getBytes(StandardCharsets.UTF_8), rust.path("failure_signature").asText()))
                .as("a failure signature is not a result signature").isFalse();
        assertThat(SealingKeyAttestation.verify(signingPublic, UUID.fromString(rust.path("agent_id").asText()),
                rust.path("generation").asLong(), rust.path("sealing_public").asText(),
                rust.path("sealing_attestation").asText()))
                .as("the sealing key the Rust agent announced").isTrue();
        // The same private key, encoded by this side: the announced key is that key's public half in
        // exactly this side's SubjectPublicKeyInfo bytes — the salt and the associated data of every
        // envelope are computed over those bytes, so an encoding that merely parses would not open.
        X25519PrivateKeyParameters rustKey = new X25519PrivateKeyParameters(labelled(rust.path("sealing_label").asText()), 0);
        assertThat(spki(rustKey)).isEqualTo(rust.path("sealing_public").asText());
    }
}
