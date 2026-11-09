package com.asmolabs.vectispire.common.domain.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.util.Arrays;

/**
 * The key that protects the secrets Vectispire stores — private SSH keys, tokens.
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
    private static final byte[] SCRYPT_SALT = "vectispire.encryption.v2".getBytes(StandardCharsets.UTF_8);

    /**
     * Base64 for exactly 32 bytes, in either alphabet.
     *
     * <p>Matching the shape is not enough on its own — the length is checked again after
     * decoding, because a 44-character string that is not valid base64 must not be taken for a
     * key. A lenient decoder would return something shorter, and the resulting key would be
     * weaker than it looks while nothing complained.
     */
    private static final Pattern BASE64_KEY = Pattern.compile("^[A-Za-z0-9+/_-]{43,44}={0,2}$");

    /**
     * The shortest passphrase taken as the key new secrets are sealed under.
     *
     * <p>The salt is fixed and public (see the class comment), so a passphrase is worth what an
     * attacker holding a copy of the database must guess, offline, at scrypt's cost — a hundred
     * milliseconds a try on one core, far less on a farm. A word, a name with a year, a
     * keyboard walk: each is under twenty characters and each falls to a dictionary. Twenty
     * characters is the length below which nothing but a human choice fits — four diceware words
     * are past it, {@code openssl rand -base64 24} is thirty-two, a generated key forty-four — so
     * the bound refuses what a person types as a password and nothing a generator produces. It is
     * a floor, not a strength meter: past it the passphrase is the operator's responsibility, as
     * the documentation says, and the recommended form remains a generated key.
     */
    public static final int MIN_PASSPHRASE_LENGTH = 20;

    /**
     * The words a template puts where a secret goes, compared once case, separators and spacing
     * are gone: {@code CHANGE_ME}, {@code change-me}, {@code ChangeMe!}, {@code <replace me>}.
     * Contained, not equal, so that {@code CHANGE_ME_generate_with_openssl_rand} is caught too —
     * past the length floor, and every bit as public.
     */
    private static final List<String> PLACEHOLDERS = List.of("changeme", "replaceme", "yourkeyhere", "putyourkeyhere");

    private final byte[] material;

    /**
     * Why {@code secret} must not be the key new secrets are sealed under, or empty when it may.
     *
     * <p><b>Not applied by {@link #derive}.</b> A previous key is the one an operator rotates
     * away from, and refusing it would leave the values sealed under it unreadable — the very
     * values the rotation exists to move. Only the current key is held to this, by whoever
     * configures it.
     *
     * <p>The answer never quotes the secret: it ends up in a log and an exception message.
     */
    public static Optional<String> refusalAsCurrentKey(String secret) {
        String trimmed = secret == null ? "" : secret.trim();
        String letters = Normalizer.normalize(trimmed, Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT)
                .replaceAll("[^\\p{L}\\p{N}]", "");
        if (PLACEHOLDERS.stream().anyMatch(letters::contains)) {
            return Optional.of("it is a template's placeholder, published with the template");
        }
        if (decodeExactKey(trimmed) != null) {
            return Optional.empty();
        }
        int length = trimmed.codePointCount(0, trimmed.length());
        if (length < MIN_PASSPHRASE_LENGTH) {
            return Optional.of("it is a passphrase of " + length + " characters, and one shorter than "
                    + MIN_PASSPHRASE_LENGTH + " is a guess away for whoever holds a copy of the database");
        }
        return Optional.empty();
    }

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
