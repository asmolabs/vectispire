package com.asmolabs.vectispire.common.domain.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
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

        // Swapping the sender's key has to fail — not decrypt into some other value the
        // recipient would then hand to git.
        //
        // **This case does not prove what its name suggests, and the one below exists because
        // of that.** Replacing the ephemeral key changes the X25519 shared secret, so it
        // changes the session key, so GCM fails on the tag no matter what the associated data
        // is. Empty the AAD entirely and this test still passes. It is a good end-to-end
        // assertion and a useless assertion about the AAD, which is exactly the shape an audit
        // found on 30 August: mutate the AAD away and only the pinned golden vector objected —
        // and it objected to the *format* changing, not to the binding being gone.
        assertThat(envelopes.open(agent, SealedEnvelope.PREFIX + Base64.getEncoder().encodeToString(payload))).isEmpty();
    }

    /**
     * The ephemeral key is genuinely fed to GCM as associated data — proved with the AAD as the
     * only variable.
     *
     * <p><b>Why this reaches past the public API.</b> Every route through {@code seal}/{@code
     * open} that disturbs the AAD also disturbs the key agreement, so no black-box test can
     * separate "the AAD is bound" from "the session key changed". This one derives the session
     * key independently — the same X25519 agreement, the same HKDF salt and info the
     * implementation uses — and then decrypts the very bytes {@code seal} produced twice: once
     * with the ephemeral key as AAD, once with none. Same key, same nonce, same ciphertext. If
     * the AAD were not part of the tag both would succeed.
     *
     * <p>Deriving it here rather than calling a package-private helper is deliberate: a test
     * that reuses the implementation's own derivation agrees with it by construction, including
     * when both are wrong. This restates the construction, so a change to either side shows up
     * as a disagreement.
     */
    @Test
    void bindsTheEphemeralKeyIntoTheTagAndNotMerelyIntoTheSessionKey() throws Exception {
        SealedEnvelope.KeyPair agent = envelopes.generateKeyPair();
        String sealed = envelopes.seal(agent.publicKey(), "deployment key");

        byte[] payload = Base64.getDecoder().decode(sealed.substring(SealedEnvelope.PREFIX.length()));

        // **The key on the wire is the SPKI encoding, not the raw 32 bytes**, so that is what
        // the AAD and the HKDF salt are made of. Taking the recipient's own encoded length
        // rather than writing 44 keeps this true if the encoding ever changes: both keys are
        // X25519 SPKI, so they are the same size by construction.
        byte[] recipientPublic = Base64.getDecoder().decode(agent.publicKey());
        int keyLength = recipientPublic.length;
        byte[] ephemeralPublic = java.util.Arrays.copyOfRange(payload, 0, keyLength);
        byte[] nonce = java.util.Arrays.copyOfRange(payload, keyLength, keyLength + 12);
        byte[] body = java.util.Arrays.copyOfRange(payload, keyLength + 12, payload.length);

        // The same agreement and the same derivation the implementation performs, restated.
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(agent.privateKey());
        byte[] shared = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(
                (X25519PublicKeyParameters) PublicKeyFactory.createKey(ephemeralPublic), shared, 0);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(ephemeralPublic);
        sha256.update(recipientPublic);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(
                shared,
                sha256.digest(),
                "vectispire:sealed-envelope:v1".getBytes(StandardCharsets.UTF_8)));
        byte[] sessionKey = new byte[32];
        hkdf.generateBytes(sessionKey, 0, sessionKey.length);

        // With the ephemeral key as associated data, the tag verifies and the secret comes back.
        assertThat(new String(decrypt(sessionKey, nonce, body, ephemeralPublic), StandardCharsets.UTF_8))
                .isEqualTo("deployment key");

        // Same key, same nonce, same bytes — only the associated data removed. If the AAD is not
        // in the tag this succeeds too, and the protection the class documents does not exist.
        assertThatThrownBy(() -> decrypt(sessionKey, nonce, body, new byte[0]))
                .isInstanceOf(InvalidCipherTextException.class);

        // And it is bound to *this* key, not merely to some non-empty value.
        byte[] otherEphemeral = Base64.getDecoder().decode(envelopes.generateKeyPair().publicKey());
        assertThatThrownBy(() -> decrypt(sessionKey, nonce, body, otherEphemeral))
                .isInstanceOf(InvalidCipherTextException.class);
    }

    /** AES-256-GCM open, with the associated data as the parameter under test. */
    private static byte[] decrypt(byte[] sessionKey, byte[] nonce, byte[] body, byte[] associatedData)
            throws InvalidCipherTextException {
        GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        cipher.init(false, new AEADParameters(new KeyParameter(sessionKey), 128, nonce, associatedData));
        byte[] out = new byte[cipher.getOutputSize(body.length)];
        int written = cipher.processBytes(body, 0, body.length, out, 0);
        written += cipher.doFinal(out, written);
        return java.util.Arrays.copyOf(out, written);
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
