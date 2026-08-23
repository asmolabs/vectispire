package com.asmolabs.zanshin.common.domain.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Base64;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.util.Arrays;

/**
 * The key that protects the secrets Zanshin stores — private SSH keys, tokens.
 *
 * <p>A type rather than a {@code byte[]}, so a caller cannot hand the cipher a buffer of the
 * wrong length, and so "this is the encryption key" is visible in a signature.
 *
 * <h2>Derivation is a real KDF</h2>
 *
 * <p>An earlier implementation truncated the configured secret to 32 bytes or padded it with
 * NULs. That is not a derivation: a short passphrase was worth exactly the entropy of its
 * characters. It had been kept only so that already-encrypted values stayed readable; nothing
 * is encrypted yet, so the defect goes with the constraint.
 *
 * <p>Two forms of secret are accepted, in this order:
 *
 * <ol>
 *   <li><b>32 random bytes in base64</b> — the recommended form, used as is. There is nothing
 *       to stretch; the entropy is already there.
 *   <li><b>a passphrase</b> — stretched with scrypt.
 * </ol>
 *
 * <p>The scrypt salt is fixed and application-specific. That is an accepted trade-off: a
 * per-deployment salt would have to be stored somewhere, and scrypt's cost is enough to make a
 * dictionary attack expensive. The only honest alternative would be refusing passphrases
 * outright, which is hostile for a self-hosted tool.
 */
public final class EncryptionKey {

    public static final int LENGTH_BYTES = 32;

    /**
     * scrypt parameters.
     *
     * <p>{@code N = 2^15} costs roughly 100 ms and about 32 MiB — imperceptible, because the
     * derivation happens <b>once</b>, at startup. Deriving per encrypted value would turn a
     * page listing twenty secrets into two seconds of CPU.
     */
    private static final int SCRYPT_N = 32_768;

    private static final int SCRYPT_R = 8;
    private static final int SCRYPT_P = 1;

    /** Fixed, application-specific, and not a secret. See the class comment. */
    private static final byte[] SCRYPT_SALT = "zanshin.encryption.v2".getBytes(StandardCharsets.UTF_8);

    /**
     * Base64 for exactly 32 bytes, in either alphabet.
     *
     * <p>Matching the shape is not enough on its own — the length is checked again after
     * decoding, because a 44-character string that is not valid base64 must not be taken for a
     * key. A lenient decoder would return something shorter, and the resulting key would be
     * weaker than it looks while nothing complained.
     */
    private static final Pattern BASE64_KEY = Pattern.compile("^[A-Za-z0-9+/_-]{43,44}={0,2}$");

    private final byte[] material;

    private EncryptionKey(byte[] material) {
        this.material = material;
    }

    /**
     * Derives the key from the configured secret.
     *
     * <p>Expensive by construction when the secret is a passphrase: call it once and keep the
     * result.
     */
    public static EncryptionKey derive(String secret) {
        byte[] provided = decodeExactKey(secret);
        if (provided != null) {
            return new EncryptionKey(provided);
        }

        // NFKC first: two byte sequences that display identically must derive the same key, or
        // a passphrase typed on another keyboard stops opening the same secrets.
        byte[] password = Normalizer.normalize(secret, Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);
        return new EncryptionKey(SCrypt.generate(password, SCRYPT_SALT, SCRYPT_N, SCRYPT_R, SCRYPT_P, LENGTH_BYTES));
    }

    /** A key ready to be placed in {@code ENCRYPTION_KEY}. */
    public static String generate() {
        byte[] material = new byte[LENGTH_BYTES];
        new SecureRandom().nextBytes(material);
        return Base64.getEncoder().encodeToString(material);
    }

    private static byte[] decodeExactKey(String secret) {
        String trimmed = secret == null ? "" : secret.trim();
        if (!BASE64_KEY.matcher(trimmed).matches()) {
            return null;
        }
        try {
            byte[] decoded = trimmed.indexOf('-') >= 0 || trimmed.indexOf('_') >= 0
                    ? Base64.getUrlDecoder().decode(trimmed)
                    : Base64.getDecoder().decode(trimmed);
            return decoded.length == LENGTH_BYTES ? decoded : null;
        } catch (IllegalArgumentException notBase64) {
            return null;
        }
    }

    byte[] material() {
        // Copied out: a caller holding the array could zero it, or keep it after this key is
        // meant to be gone.
        return Arrays.clone(material);
    }

    /**
     * Two keys are equal when their material is.
     *
     * <p>Compared in constant time, and used for one thing: dropping a key that appears twice
     * in the configuration, so a rotated deployment does not try the same key as current and
     * again as previous.
     */
    @Override
    public boolean equals(Object other) {
        return other instanceof EncryptionKey key && Arrays.constantTimeAreEqual(material, key.material);
    }

    /**
     * Deliberately constant.
     *
     * <p>A hash of the material is a 32-bit oracle on a secret, cheap to put in a heap dump or
     * a debugger. The lists this class lives in hold two or three entries, so the degenerate
     * bucket costs nothing measurable.
     */
    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public String toString() {
        // Never the material. A key that prints itself ends up in a log, an exception message
        // and a bug report, in that order.
        return "EncryptionKey[32 bytes]";
    }
}
