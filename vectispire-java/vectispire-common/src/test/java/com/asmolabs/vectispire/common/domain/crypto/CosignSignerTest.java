package com.asmolabs.zanshin.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.attestation.DsseEnvelope;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the Cosign and DSSE cryptographic signer")
class CosignSignerTest {

    @Test
    @DisplayName("generates ECDSA P-256 key pair and serializes to/from PEM")
    void generatesAndParsesPemKeys() {
        KeyPair keyPair = CosignSigner.generateKeyPair();
        String pubPem = CosignSigner.toPem(keyPair.getPublic());
        String privPem = CosignSigner.toPem(keyPair.getPrivate());

        assertThat(pubPem).contains("-----BEGIN PUBLIC KEY-----");
        assertThat(privPem).contains("-----BEGIN PRIVATE KEY-----");

        PublicKey parsedPub = CosignSigner.parsePublicKey(pubPem);
        PrivateKey parsedPriv = CosignSigner.parsePrivateKey(privPem);

        assertThat(parsedPub.getAlgorithm()).isEqualTo("EC");
        assertThat(parsedPriv.getAlgorithm()).isEqualTo("EC");
        assertThat(parsedPub.getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
    }

    @Test
    @DisplayName("signs payload and verifies detached signature")
    void signsAndVerifiesPayload() {
        KeyPair keyPair = CosignSigner.generateKeyPair();
        byte[] payload = "{\"predicate\": \"compliant\", \"gate\": true}".getBytes(StandardCharsets.UTF_8);

        String signature = CosignSigner.sign(payload, keyPair.getPrivate());
        assertThat(signature).isNotBlank();

        boolean verified = CosignSigner.verify(payload, signature, keyPair.getPublic());
        assertThat(verified).isTrue();

        byte[] tampered = "{\"predicate\": \"compliant\", \"gate\": false}".getBytes(StandardCharsets.UTF_8);
        boolean tamperedVerification = CosignSigner.verify(tampered, signature, keyPair.getPublic());
        assertThat(tamperedVerification).isFalse();

        KeyPair otherKey = CosignSigner.generateKeyPair();
        boolean wrongKeyVerification = CosignSigner.verify(payload, signature, otherKey.getPublic());
        assertThat(wrongKeyVerification).isFalse();
    }

    @Test
    @DisplayName("wraps payload in signed DSSE envelope and verifies statement")
    void wrapsAndVerifiesDsseEnvelope() {
        KeyPair keyPair = CosignSigner.generateKeyPair();
        String keyId = CosignSigner.computeKeyId(keyPair.getPublic());
        byte[] payload = "{\"_type\": \"https://in-toto.io/Statement/v0.1\"}".getBytes(StandardCharsets.UTF_8);

        DsseEnvelope envelope = CosignSigner.wrapAndSignDsse(
                DsseEnvelope.IN_TOTO_PAYLOAD_TYPE,
                payload,
                keyPair.getPrivate(),
                keyId);

        assertThat(envelope.payloadType()).isEqualTo("application/vnd.in-toto+json");
        assertThat(envelope.signatures()).hasSize(1);
        assertThat(envelope.signatures().get(0).keyid()).isEqualTo(keyId);

        boolean verified = CosignSigner.verifyDsse(envelope, keyPair.getPublic());
        assertThat(verified).isTrue();

        DsseEnvelope tamperedEnvelope = new DsseEnvelope(
                envelope.payloadType(),
                java.util.Base64.getEncoder().encodeToString("{\"_type\": \"corrupted\"}".getBytes(StandardCharsets.UTF_8)),
                envelope.signatures());
        assertThat(CosignSigner.verifyDsse(tamperedEnvelope, keyPair.getPublic())).isFalse();
    }
}
