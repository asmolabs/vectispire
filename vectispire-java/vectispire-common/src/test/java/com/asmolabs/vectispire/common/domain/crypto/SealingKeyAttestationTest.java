package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the signature on an agent's sealing key")
class SealingKeyAttestationTest {

    private static final UUID AGENT = UUID.fromString("7f3c2a10-4b5d-4e6f-8a9b-0c1d2e3f4a5b");
    private static final long GENERATION = 1_790_000_000_000L;

    private final ResultAttestation.KeyPair signing = ResultAttestation.generate();
    private final String sealing = new SealedEnvelope().generateKeyPair().publicKey();

    @Test
    @DisplayName("a key signed with the pinned key verifies")
    void roundTrip() {
        String signature = SealingKeyAttestation.sign(signing.privateKey(), AGENT, GENERATION, sealing);

        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, sealing, signature)).isTrue();
    }

    /**
     * The format, pinned from outside the class: the digest is rebuilt here with the JDK's own
     * SHA-256 and signed with BouncyCastle directly. A change to any part of the message — its
     * context, its order, a separator — fails this, and would otherwise pass every round trip,
     * while breaking every agent built before it.
     */
    @Test
    @DisplayName("the signature covers exactly context ‖ agent id ‖ generation ‖ sha256(key bytes)")
    void theExactBytes() throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.writeBytes("vectispire:agent-sealing-key:v1".getBytes(StandardCharsets.UTF_8));
        message.write(0);
        message.writeBytes("7f3c2a10-4b5d-4e6f-8a9b-0c1d2e3f4a5b".getBytes(StandardCharsets.UTF_8));
        message.write(0);
        message.writeBytes("1790000000000".getBytes(StandardCharsets.UTF_8));
        message.write(0);
        message.writeBytes(sha256.digest(Base64.getDecoder().decode(sealing)));
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(message.toByteArray());

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, new Ed25519PrivateKeyParameters(Base64.getDecoder().decode(signing.privateKey()), 0));
        signer.update(digest, 0, digest.length);
        String independent = Base64.getEncoder().encodeToString(signer.generateSignature());

        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, sealing, independent)).isTrue();
        // Ed25519 is deterministic: the class signs the same bytes, not merely bytes that verify.
        assertThat(SealingKeyAttestation.sign(signing.privateKey(), AGENT, GENERATION, sealing)).isEqualTo(independent);
    }

    @Test
    @DisplayName("an announcement made for another agent is refused")
    void anotherAgent() {
        String signature = SealingKeyAttestation.sign(signing.privateKey(), AGENT, GENERATION, sealing);

        assertThat(SealingKeyAttestation.verify(signing.publicKey(), UUID.randomUUID(), GENERATION, sealing, signature))
                .isFalse();
    }

    @Test
    @DisplayName("an announcement replayed under another generation is refused")
    void anotherGeneration() {
        String signature = SealingKeyAttestation.sign(signing.privateKey(), AGENT, GENERATION, sealing);

        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION + 1, sealing, signature))
                .isFalse();
    }

    @Test
    @DisplayName("a signature moved onto a substituted sealing key is refused")
    void anotherSealingKey() {
        String signature = SealingKeyAttestation.sign(signing.privateKey(), AGENT, GENERATION, sealing);
        String substituted = new SealedEnvelope().generateKeyPair().publicKey();

        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, substituted, signature))
                .isFalse();
    }

    @Test
    @DisplayName("a key signed by anybody but the pinned key is refused")
    void anotherSigner() {
        ResultAttestation.KeyPair other = ResultAttestation.generate();
        String signature = SealingKeyAttestation.sign(other.privateKey(), AGENT, GENERATION, sealing);

        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, sealing, signature)).isFalse();
    }

    /**
     * The domain separation, from the side that matters: the agent signs result bodies with the same
     * key, and a body is whatever the agent chose to send. No result signature may pass for a key
     * announcement, whatever the body.
     */
    @Test
    @DisplayName("a result signature by the same key is not a key announcement")
    void noCrossProtocolReuse() throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        ByteArrayOutputStream sameFieldsOtherContext = new ByteArrayOutputStream();
        sameFieldsOtherContext.writeBytes("vectispire:agent-result:v1".getBytes(StandardCharsets.UTF_8));
        sameFieldsOtherContext.write(0);
        sameFieldsOtherContext.writeBytes(AGENT.toString().getBytes(StandardCharsets.UTF_8));
        sameFieldsOtherContext.write(0);
        sameFieldsOtherContext.writeBytes(Long.toString(GENERATION).getBytes(StandardCharsets.UTF_8));
        sameFieldsOtherContext.write(0);
        sameFieldsOtherContext.writeBytes(sha256.digest(Base64.getDecoder().decode(sealing)));
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(sameFieldsOtherContext.toByteArray());
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, new Ed25519PrivateKeyParameters(Base64.getDecoder().decode(signing.privateKey()), 0));
        signer.update(digest, 0, digest.length);
        String otherContext = Base64.getEncoder().encodeToString(signer.generateSignature());

        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, sealing, otherContext)).isFalse();

        String resultSignature = ResultAttestation.sign(
                signing.privateKey(), GENERATION, Base64.getDecoder().decode(sealing));
        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, sealing, resultSignature))
                .isFalse();
    }

    @Test
    @DisplayName("anything malformed is a refusal, never an exception")
    void malformed() {
        String signature = SealingKeyAttestation.sign(signing.privateKey(), AGENT, GENERATION, sealing);

        assertThat(SealingKeyAttestation.verify(null, AGENT, GENERATION, sealing, signature)).isFalse();
        assertThat(SealingKeyAttestation.verify(signing.publicKey(), null, GENERATION, sealing, signature)).isFalse();
        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, 0, sealing, signature)).isFalse();
        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, "not-a-key", signature)).isFalse();
        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, sealing, "c2hvcnQ=")).isFalse();
        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, sealing, null)).isFalse();
        // An Ed25519 public key where the sealing key belongs: readable, the wrong curve.
        assertThat(SealingKeyAttestation.verify(signing.publicKey(), AGENT, GENERATION, signing.publicKey(), signature))
                .isFalse();
    }

    @Test
    @DisplayName("the agent refuses to sign what the control plane would refuse")
    void signingRefusesNonsense() {
        assertThatThrownBy(() -> SealingKeyAttestation.sign("c2hvcnQ=", AGENT, GENERATION, sealing))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SealingKeyAttestation.sign(signing.privateKey(), AGENT, -1, sealing))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SealingKeyAttestation.sign(signing.privateKey(), AGENT, GENERATION, "not-a-key"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
