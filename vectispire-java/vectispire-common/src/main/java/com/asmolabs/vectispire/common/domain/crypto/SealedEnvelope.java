package com.asmolabs.vectispire.common.domain.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;

/**
 * A secret encrypted <b>for one specific recipient</b>.
 *
 * <p><b>What TLS does not give.</b> A repository's deployment key travels from the control
 * plane to a remote agent. TLS protects it end to end <em>provided nobody terminates TLS on
 * the way</em> — and most deployments have a reverse proxy. At that point the SSH key is in
 * the clear: in a memory dump, in a debug log, and to whoever administers the proxy. Sealing
 * takes that proxy out of the trust boundary: the agent publishes an ephemeral public key on
 * every claim, the control plane seals for it, and the private half never leaves the agent's
 * process — <b>nothing is written at rest</b>.
 *
 * <p><b>X25519, then HKDF, then AES-256-GCM.</b> The classic sealed box, written against
 * BouncyCastle's lightweight API for the reason given in {@link Digests}: which
 * implementation runs should not be a property of the host. A one-shot ephemeral pair on the
 * sender's side gives a shared secret, HKDF derives a session key, GCM encrypts and
 * authenticates.
 *
 * <p><b>The sender's public key is covered by the authentication.</b> It travels as
 * associated data, so an envelope whose ephemeral key was swapped fails to open rather than
 * opening into something else.
 */
public final class SealedEnvelope {

    /** An envelope's prefix. Its presence is what tells the agent it has to unseal. */
    public static final String PREFIX = "sealed:v1:";

    /** Separates this derivation from any other built on the same exchange. */
    private static final byte[] HKDF_INFO = "vectispire:sealed-envelope:v1".getBytes(StandardCharsets.UTF_8);

    private static final int SESSION_KEY_LENGTH_BYTES = 32;
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;

    private final SecureRandom random;

    public SealedEnvelope() {
        this(new SecureRandom());
    }

    public SealedEnvelope(SecureRandom random) {
        this.random = random;
    }

    /**
     * A recipient's pair, held in memory for the life of one process.
     *
     * <p>{@code publicKey} is base64 of the SPKI encoding — publishable, worth nothing on its
     * own. The private half is a live BouncyCastle parameter object and is deliberately not
     * serializable to anything: a restarted agent is a new recipient, and there is no key file
     * to protect, rotate, or forget.
     */
    public record KeyPair(String publicKey, X25519PrivateKeyParameters privateKey) {}

    /** A fresh recipient. Regenerated on every start, never written. */
    public KeyPair generateKeyPair() {
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(new X25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        return new KeyPair(
                encodePublicKey((X25519PublicKeyParameters) pair.getPublic()),
                (X25519PrivateKeyParameters) pair.getPrivate());
    }

    /**
     * Seals a secret for the holder of this public key.
     *
     * <p>Throws when the key is unreadable, and <b>refusing is the point</b>: handing the
     * secret back in the clear "because sealing failed" would cancel the entire protection at
     * the one moment it matters. Callers that want to decide beforehand ask
     * {@link #isUsablePublicKey} first.
     */
    public String seal(String recipientPublicKey, String plainText) {
        X25519PublicKeyParameters recipient = parsePublicKey(recipientPublicKey)
                .orElseThrow(() -> new IllegalArgumentException("The recipient's sealing key is not a usable X25519 public key."));

        // One ephemeral pair per envelope, not per agent: two seals for the same recipient
        // then share no key material, so recovering one session key opens one envelope.
        KeyPair ephemeral = generateKeyPair();
        byte[] ephemeralPublic = Base64.getDecoder().decode(ephemeral.publicKey());
        byte[] recipientPublic = Base64.getDecoder().decode(recipientPublicKey);

        byte[] sessionKey = deriveSessionKey(agree(ephemeral.privateKey(), recipient), ephemeralPublic, recipientPublic);

        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        random.nextBytes(nonce);

        byte[] plain = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] output = new byte[plain.length + TAG_LENGTH_BYTES];
        GCMModeCipher cipher = newCipher(sessionKey, nonce, ephemeralPublic, true);
        try {
            int written = cipher.processBytes(plain, 0, plain.length, output, 0);
            cipher.doFinal(output, written);
        } catch (InvalidCipherTextException impossible) {
            // Encryption verifies no tag; this branch is unreachable.
            throw new IllegalStateException("GCM encryption failed", impossible);
        }

        return PREFIX + Base64.getEncoder().encodeToString(Arrays.concatenate(ephemeralPublic, nonce, output));
    }

    /**
     * Opens an envelope with the private half that matches it.
     *
     * <p>Empty for anything that is not exactly the expected envelope — wrong recipient,
     * altered content, unknown format. Never an exception: the only useful conclusion for the
     * caller is "I did not receive the key", and the three causes are indistinguishable on
     * purpose. Telling them apart tells whoever is probing which of the three they got right.
     */
    public Optional<String> open(KeyPair keyPair, String envelope) {
        if (!isSealed(envelope)) {
            return Optional.empty();
        }

        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(envelope.substring(PREFIX.length()));
        } catch (IllegalArgumentException notBase64) {
            return Optional.empty();
        }

        // The sender's key is as long as ours: both are X25519 in the same encoding. Read from
        // our own rather than assumed, so a future encoding change breaks the split visibly
        // instead of shifting the field boundary by a byte.
        int publicKeyLength = Base64.getDecoder().decode(keyPair.publicKey()).length;
        if (payload.length < publicKeyLength + NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES) {
            return Optional.empty();
        }

        byte[] ephemeralPublic = Arrays.copyOfRange(payload, 0, publicKeyLength);
        byte[] nonce = Arrays.copyOfRange(payload, publicKeyLength, publicKeyLength + NONCE_LENGTH_BYTES);
        byte[] body = Arrays.copyOfRange(payload, publicKeyLength + NONCE_LENGTH_BYTES, payload.length);

        Optional<X25519PublicKeyParameters> sender = parsePublicKey(Base64.getEncoder().encodeToString(ephemeralPublic));
        if (sender.isEmpty()) {
            return Optional.empty();
        }

        byte[] sessionKey = deriveSessionKey(
                agree(keyPair.privateKey(), sender.get()),
                ephemeralPublic,
                Base64.getDecoder().decode(keyPair.publicKey()));

        GCMModeCipher cipher = newCipher(sessionKey, nonce, ephemeralPublic, false);
        byte[] output = new byte[cipher.getOutputSize(body.length)];
        try {
            int written = cipher.processBytes(body, 0, body.length, output, 0);
            written += cipher.doFinal(output, written);
            return Optional.of(new String(output, 0, written, StandardCharsets.UTF_8));
        } catch (InvalidCipherTextException tagDidNotVerify) {
            return Optional.empty();
        }
    }

    /** Is this value a sealed envelope rather than a secret in the clear? */
    public static boolean isSealed(String value) {
        return value != null && value.startsWith(PREFIX);
    }

    /**
     * A readable public key?
     *
     * <p>Asked before sealing so a claim can decline cleanly instead of discovering the problem
     * as an exception halfway through. <b>Readable is not enough — it has to be X25519.</b> An
     * RSA key decodes perfectly and will not survive the exchange at any price, which is why
     * this checks the parsed type and not just the encoding.
     */
    public static boolean isUsablePublicKey(String value) {
        return parsePublicKey(value).isPresent();
    }

    private static Optional<X25519PublicKeyParameters> parsePublicKey(String value) {
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }
        try {
            return PublicKeyFactory.createKey(Base64.getDecoder().decode(value))
                    instanceof X25519PublicKeyParameters key
                    ? Optional.of(key)
                    : Optional.empty();
        } catch (IOException | IllegalArgumentException | ClassCastException unreadable) {
            return Optional.empty();
        }
    }

    private static String encodePublicKey(X25519PublicKeyParameters key) {
        try {
            return Base64.getEncoder()
                    .encodeToString(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key).getEncoded());
        } catch (IOException impossible) {
            // The encoding of a key we just generated cannot fail.
            throw new IllegalStateException("X25519 public key could not be encoded", impossible);
        }
    }

    private static byte[] agree(X25519PrivateKeyParameters ours, X25519PublicKeyParameters theirs) {
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(ours);
        byte[] shared = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(theirs, shared, 0);
        return shared;
    }

    /**
     * The session key, bound to <b>both</b> public keys of the exchange.
     *
     * <p>They go into the salt, and that is what stops an envelope being replayed towards
     * another recipient: the shared secret would be identical, the derived key would not.
     */
    private static byte[] deriveSessionKey(byte[] shared, byte[] ephemeralPublic, byte[] recipientPublic) {
        byte[] salt = Digests.sha256(ephemeralPublic, recipientPublic);
        HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
        generator.init(new HKDFParameters(shared, salt, HKDF_INFO));
        byte[] sessionKey = new byte[SESSION_KEY_LENGTH_BYTES];
        generator.generateBytes(sessionKey, 0, sessionKey.length);
        return sessionKey;
    }

    private static GCMModeCipher newCipher(byte[] sessionKey, byte[] nonce, byte[] associatedData, boolean forEncryption) {
        GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        cipher.init(forEncryption, new AEADParameters(new KeyParameter(sessionKey), TAG_LENGTH_BITS, nonce, associatedData));
        return cipher;
    }
}
