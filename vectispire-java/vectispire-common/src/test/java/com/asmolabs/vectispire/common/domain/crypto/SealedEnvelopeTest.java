package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.jupiter.api.Test;

class SealedEnvelopeTest {

    private final SealedEnvelope envelopes = new SealedEnvelope();

    @Test
    void sealsAndOpensForTheIntendedRecipient() {
        SealedEnvelope.KeyPair agent = envelopes.generateKeyPair();

        String testSecret = "test-envelope-secret-payload";
        String sealed = envelopes.seal(agent.publicKey(), testSecret);

        assertThat(sealed).startsWith(SealedEnvelope.PREFIX);
        assertThat(envelopes.open(agent, sealed)).contains(testSecret);
    }

    @Test
    void doesNotOpenForAnotherRecipient() {
        SealedEnvelope.KeyPair intended = envelopes.generateKeyPair();
        SealedEnvelope.KeyPair eavesdropper = envelopes.generateKeyPair();

        String sealed = envelopes.seal(intended.publicKey(), "deployment key");

        assertThat(envelopes.open(eavesdropper, sealed)).isEmpty();
    }

    @Test
    void twoSealsOfTheSameSecretDiffer() {
        SealedEnvelope.KeyPair agent = envelopes.generateKeyPair();

        // One ephemeral pair per envelope: identical plaintexts must not produce identical
        // ciphertexts, or the traffic tells an observer which repositories share a key.
        assertThat(envelopes.seal(agent.publicKey(), "same")).isNotEqualTo(envelopes.seal(agent.publicKey(), "same"));
    }

    @Test
    void refusesAnEnvelopeWhoseCiphertextWasAltered() {
        SealedEnvelope.KeyPair agent = envelopes.generateKeyPair();
        String sealed = envelopes.seal(agent.publicKey(), "deployment key");

        byte[] payload = Base64.getDecoder().decode(sealed.substring(SealedEnvelope.PREFIX.length()));
        payload[payload.length - 1] ^= 0x01;

        assertThat(envelopes.open(agent, SealedEnvelope.PREFIX + Base64.getEncoder().encodeToString(payload))).isEmpty();
    }

    @Test
    void refusesAnEnvelopeWhoseEphemeralKeyWasReplaced() {
        SealedEnvelope.KeyPair agent = envelopes.generateKeyPair();
        String sealed = envelopes.seal(agent.publicKey(), "deployment key");

        byte[] payload = Base64.getDecoder().decode(sealed.substring(SealedEnvelope.PREFIX.length()));
        byte[] otherEphemeral = Base64.getDecoder().decode(envelopes.generateKeyPair().publicKey());
        System.arraycopy(otherEphemeral, 0, payload, 0, otherEphemeral.length);

        // The sender's key is associated data, so swapping it has to fail authentication —
        // not decrypt into some other value the recipient would then hand to git.
        assertThat(envelopes.open(agent, SealedEnvelope.PREFIX + Base64.getEncoder().encodeToString(payload))).isEmpty();
    }

    @Test
    void treatsAnythingUnprefixedAsNotSealed() {
        SealedEnvelope.KeyPair agent = envelopes.generateKeyPair();

        assertThat(SealedEnvelope.isSealed(null)).isFalse();
        assertThat(SealedEnvelope.isSealed("unsealed-plain-test-content")).isFalse();
        assertThat(envelopes.open(agent, "unsealed-plain-test-content")).isEmpty();
    }

    @Test
    void refusesTruncatedAndUndecodablePayloads() {
        SealedEnvelope.KeyPair agent = envelopes.generateKeyPair();

        assertThat(envelopes.open(agent, SealedEnvelope.PREFIX + "!!not base64!!")).isEmpty();
        assertThat(envelopes.open(agent, SealedEnvelope.PREFIX + Base64.getEncoder().encodeToString(new byte[8]))).isEmpty();
    }

    @Test
    void acceptsOnlyAnX25519PublicKey() {
        assertThat(SealedEnvelope.isUsablePublicKey(envelopes.generateKeyPair().publicKey())).isTrue();

        assertThat(SealedEnvelope.isUsablePublicKey(null)).isFalse();
        assertThat(SealedEnvelope.isUsablePublicKey("")).isFalse();
        assertThat(SealedEnvelope.isUsablePublicKey("not base64 at all")).isFalse();
        // Well-formed, readable, and useless here: an RSA key would fail inside the exchange,
        // which is exactly the discovery this predicate exists to make earlier.
        assertThat(SealedEnvelope.isUsablePublicKey(rsaPublicKey())).isFalse();
    }

    @Test
    void refusesToSealForAKeyItCannotUse() {
        // Refusing beats returning the secret in the clear "because sealing failed".
        assertThatThrownBy(() -> envelopes.seal(rsaPublicKey(), "deployment key"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("X25519");
    }

    /** A perfectly valid public key of the wrong kind. 1024 bits: this is a parser test. */
    private static String rsaPublicKey() {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 1024, 80));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        try {
            SubjectPublicKeyInfo info =
                    SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo((RSAKeyParameters) pair.getPublic());
            return Base64.getEncoder().encodeToString(info.getEncoded());
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /**
     * One envelope from 26 August 2026, opened by a recipient key that never changes.
     *
     * <p><b>Every other test here seals before it opens, and that hides the failure that matters
     * for this class.</b> A remote agent publishes its sealing key and the control plane seals to
     * it; the two are separate deployments and they are not upgraded together. So the question a
     * round trip cannot ask is whether a control plane built today still speaks to an agent built
     * before it — a changed HKDF info string, a different nonce length, a new {@code sealed:v1:}
     * prefix, and the handshake stops working in the field while every test stays green.
     *
     * <p>Unlike {@code SecretCipher}'s vector, nothing stored becomes unreadable: what breaks is a
     * live protocol between versions. That is why this arrives second, and why it is still worth
     * having — a protocol break discovered by an operator is discovered at the worst moment.
     *
     * <p>The recipient's private scalar says what it is in its own bytes:
     * {@code kat-envelope-recipient-key-32byt}.
     */
    @Test
    void anEnvelopeSealedByAnEarlierBuildStillOpens() {
        SealedEnvelope envelopes = new SealedEnvelope();
        X25519PrivateKeyParameters recipient = new X25519PrivateKeyParameters(
                "kat-envelope-recipient-key-32byt".getBytes(java.nio.charset.StandardCharsets.UTF_8), 0);
        SealedEnvelope.KeyPair keyPair = new SealedEnvelope.KeyPair(
                "MCowBQYDK2VuAyEAXLnFpdiovM3OsClUD9dvTwANjDGuYcfrpUyYSzNjuEU=", recipient);

        String sealedOn20260826 = "sealed:v1:MCowBQYDK2VuAyEAbncNOCviu61zaY2RNZTM0JDn5RIXih70OvIL7rj5lX5"
                + "+BjJpVq6SAeNMd1aqXW+6kzFUWtHWaxIpjbhVwiueZ5f1ltFp3745AF81hokYGYQ67eHAM8m1XV7E7JEh";

        assertThat(envelopes.open(keyPair, sealedOn20260826)).contains("agent-registration-token-not-real");
    }

    /**
     * The pair to the vector above: an envelope addressed elsewhere must stay shut.
     *
     * <p>Without this, a build that had stopped deriving the session key from the recipient at all
     * would pass the vector — it would open everything, including that one.
     */
    @Test
    void thatEnvelopeDoesNotOpenForAnotherRecipient() {
        SealedEnvelope envelopes = new SealedEnvelope();
        SealedEnvelope.KeyPair stranger = envelopes.generateKeyPair();

        String sealedOn20260826 = "sealed:v1:MCowBQYDK2VuAyEAbncNOCviu61zaY2RNZTM0JDn5RIXih70OvIL7rj5lX5"
                + "+BjJpVq6SAeNMd1aqXW+6kzFUWtHWaxIpjbhVwiueZ5f1ltFp3745AF81hokYGYQ67eHAM8m1XV7E7JEh";

        assertThat(envelopes.open(stranger, sealedOn20260826)).isEmpty();
    }

}
