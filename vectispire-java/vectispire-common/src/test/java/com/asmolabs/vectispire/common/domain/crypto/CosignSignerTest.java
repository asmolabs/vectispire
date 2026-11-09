package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.attestation.DsseEnvelope;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
    @DisplayName("a parsed key is the same whether or not BouncyCastle has been registered, as sshd does on a clone")
    void parsingDoesNotDependOnTheRegisteredProviders() {
        // The test above failed now and then on "ECDSA": Apache MINA sshd registers BouncyCastle the
        // first time JGit clones over SSH, and the PEM converter then built a BouncyCastle key under
        // that name. Whichever test ran first in the JVM decided — so this one registers it itself.
        KeyPair keyPair = CosignSigner.generateKeyPair();
        String pubPem = CosignSigner.toPem(keyPair.getPublic());
        String privPem = CosignSigner.toPem(keyPair.getPrivate());
        String sec1Pem = sec1(keyPair.getPrivate());

        boolean added = Security.addProvider(new BouncyCastleProvider()) != -1;
        try {
            assertThat(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)).isNotNull();
            PublicKey parsedPub = CosignSigner.parsePublicKey(pubPem);
            PrivateKey parsedPriv = CosignSigner.parsePrivateKey(privPem);

            assertThat(parsedPub.getAlgorithm()).isEqualTo("EC");
            assertThat(parsedPriv.getAlgorithm()).isEqualTo("EC");
            assertThat(CosignSigner.parsePrivateKey(sec1Pem).getAlgorithm()).isEqualTo("EC");
            assertThat(parsedPub.getClass()).isEqualTo(keyPair.getPublic().getClass());
            assertThat(CosignSigner.computeKeyId(parsedPub)).isEqualTo(CosignSigner.computeKeyId(keyPair.getPublic()));
            byte[] payload = "signed across providers".getBytes(StandardCharsets.UTF_8);
            assertThat(CosignSigner.verify(payload, CosignSigner.sign(payload, parsedPriv), keyPair.getPublic())).isTrue();
        } finally {
            // Only what this test added: sshd keeps using the provider it registered.
            if (added) {
                Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            }
        }
    }

    /** The key as OpenSSL writes it by default, {@code BEGIN EC PRIVATE KEY}, which parses as a key pair. */
    private static String sec1(PrivateKey key) {
        try {
            java.io.StringWriter out = new java.io.StringWriter();
            try (org.bouncycastle.util.io.pem.PemWriter writer = new org.bouncycastle.util.io.pem.PemWriter(out)) {
                // With the curve named inside, as OpenSSL writes it: the parser has nothing else to go on.
                byte[] sec1 = new org.bouncycastle.asn1.sec.ECPrivateKey(
                                256,
                                ((java.security.interfaces.ECPrivateKey) key).getS(),
                                new org.bouncycastle.asn1.x9.X962Parameters(
                                        org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp256r1))
                        .getEncoded();
                writer.writeObject(new org.bouncycastle.util.io.pem.PemObject("EC PRIVATE KEY", sec1));
            }
            return out.toString();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
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

    @Test
    @DisplayName("the pre-authentication encoding is the specification's, byte for byte")
    void preAuthenticationEncodingMatchesTheSpecification() {
        // The example given by the DSSE specification itself.
        assertThat(new String(
                        CosignSigner.preAuthenticationEncoding(
                                "http://example.com/HelloWorld", "hello world".getBytes(StandardCharsets.UTF_8)),
                        StandardCharsets.UTF_8))
                .isEqualTo("DSSEv1 29 http://example.com/HelloWorld 11 hello world");
    }

    @Test
    @DisplayName("the signature covers the payload type: a relabelled envelope does not verify")
    void theTypeIsAuthenticated() {
        // Only the payload was signed, so a statement could be presented under any type and still
        // verify — and in-toto and cosign tooling, which check the encoding, refused it.
        KeyPair keyPair = CosignSigner.generateKeyPair();
        byte[] payload = "{\"_type\": \"https://in-toto.io/Statement/v1\"}".getBytes(StandardCharsets.UTF_8);
        DsseEnvelope envelope = CosignSigner.wrapAndSignDsse(
                DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload, keyPair.getPrivate(), "k");

        DsseEnvelope relabelled = new DsseEnvelope("application/json", envelope.payload(), envelope.signatures());
        assertThat(CosignSigner.verifyDsse(relabelled, keyPair.getPublic())).isFalse();

        // And what is signed is the encoding, not the raw payload.
        String signature = envelope.signatures().getFirst().sig();
        assertThat(CosignSigner.verify(payload, signature, keyPair.getPublic())).isFalse();
        assertThat(CosignSigner.verify(
                        CosignSigner.preAuthenticationEncoding(DsseEnvelope.IN_TOTO_PAYLOAD_TYPE, payload),
                        signature,
                        keyPair.getPublic()))
                .isTrue();
    }
}
