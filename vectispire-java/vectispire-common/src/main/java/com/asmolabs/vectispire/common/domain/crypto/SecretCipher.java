package com.asmolabs.zanshin.common.domain.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * Encryption at rest, AES-256-GCM through BouncyCastle.
 *
 * <p><b>AEAD, never a bare cipher.</b> Confidentiality without authentication would let anyone
 * able to write to the database flip bits in a stored SSH key and watch what happens; the GCM
 * tag is what turns that into a decryption failure.
 *
 * <p><b>The associated data binds a ciphertext to its row.</b> Without it, somebody able to
 * write to the database copies key A's ciphertext into row B: it decrypts cleanly, and
 * repository A is cloned with B's key — silently, with no error anywhere. That is the whole
 * reason {@link #privateKeyContext} exists and why there is no decrypt path that skips it.
 *
 * <p>The format carries a version: {@code v2:base64(iv ‖ ciphertext ‖ tag)}. No {@code v1} is
 * left to read, but the next format change will not have to guess.
 */
public final class SecretCipher {

    private static final String FORMAT_PREFIX = "v2:";
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;

    private final SecureRandom random;

    public SecretCipher() {
        this(new SecureRandom());
    }

    public SecretCipher(SecureRandom random) {
        this.random = random;
    }

    /** A ciphertext's state with respect to the configured keys. */
    public enum SecretState {
        CURRENT,
        PREVIOUS_KEY,
        UNREADABLE
    }

    public String encrypt(EncryptionKey key, String plainText, String context) {
        if (plainText == null || plainText.isEmpty()) {
            return plainText;
        }

        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        random.nextBytes(nonce);

        byte[] plain = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] output = new byte[plain.length + TAG_LENGTH_BYTES];

        GCMModeCipher cipher = newCipher(key, nonce, context, true);
        try {
            int written = cipher.processBytes(plain, 0, plain.length, output, 0);
            cipher.doFinal(output, written);
        } catch (InvalidCipherTextException impossible) {
            // Encryption has no tag to verify; this branch cannot be reached.
            throw new IllegalStateException("GCM encryption failed", impossible);
        }

        return FORMAT_PREFIX + Base64.getEncoder().encodeToString(Arrays.concatenate(nonce, output));
    }

    /**
     * Empty when this key does not read this value — <b>never an exception</b>.
     *
     * <p>The caller tries several keys in turn, so a failure is the normal case during
     * rotation. Throwing would make the ordinary path look like a fault, and the log would fill
     * with stack traces nobody should act on.
     */
    public Optional<String> decrypt(EncryptionKey key, String encrypted, String context) {
        if (encrypted == null || !encrypted.startsWith(FORMAT_PREFIX)) {
            return Optional.empty();
        }

        byte[] combined;
        try {
            combined = Base64.getDecoder().decode(encrypted.substring(FORMAT_PREFIX.length()));
        } catch (IllegalArgumentException notBase64) {
            return Optional.empty();
        }
        if (combined.length < NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES) {
            return Optional.empty();
        }

        byte[] nonce = Arrays.copyOfRange(combined, 0, NONCE_LENGTH_BYTES);
        byte[] body = Arrays.copyOfRange(combined, NONCE_LENGTH_BYTES, combined.length);

        GCMModeCipher cipher = newCipher(key, nonce, context, false);
        byte[] output = new byte[cipher.getOutputSize(body.length)];
        try {
            int written = cipher.processBytes(body, 0, body.length, output, 0);
            written += cipher.doFinal(output, written);
            return Optional.of(new String(output, 0, written, StandardCharsets.UTF_8));
        } catch (InvalidCipherTextException tagDidNotVerify) {
            // Wrong key, wrong associated data, or an altered value. All three look alike from
            // here, and that is intended: distinguishing them tells an attacker which of the
            // three they got right.
            return Optional.empty();
        }
    }

    /**
     * Tries the keys in order.
     *
     * <p>The current key first, so a value that has already been rotated never declares itself
     * old. There is <b>no fallback without associated data</b>: such a fallback would exist
     * only to read rows written before contexts did, and it is one more way of accepting a
     * relocated ciphertext.
     */
    public Decrypted decryptWithAny(List<EncryptionKey> keys, String encrypted, String context) {
        for (int index = 0; index < keys.size(); index++) {
            Optional<String> plainText = decrypt(keys.get(index), encrypted, context);
            if (plainText.isPresent()) {
                return new Decrypted(plainText.get(), index == 0 ? SecretState.CURRENT : SecretState.PREVIOUS_KEY);
            }
        }
        return new Decrypted("", SecretState.UNREADABLE);
    }

    public record Decrypted(String plainText, SecretState state) {}

    /**
     * Where a private key lives, as one definition.
     *
     * <p>Encrypting under one context and decrypting under another makes the value unreadable,
     * so this string may only ever be built here.
     */
    public static String privateKeyContext(String keyId) {
        return "ssh_key:" + keyId + ":private_key";
    }

    /** Constant-time comparison, for cases where the compared value is itself a secret. */
    public static boolean secretEquals(String left, String right) {
        return Arrays.constantTimeAreEqual(
                left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }

    private static GCMModeCipher newCipher(EncryptionKey key, byte[] nonce, String context, boolean forEncryption) {
        GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        byte[] associated = context == null ? null : context.getBytes(StandardCharsets.UTF_8);
        cipher.init(forEncryption, new AEADParameters(new KeyParameter(key.material()), TAG_LENGTH_BITS, nonce, associated));
        return cipher;
    }
}
