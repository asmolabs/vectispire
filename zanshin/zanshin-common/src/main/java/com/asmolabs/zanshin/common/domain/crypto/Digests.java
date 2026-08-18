package com.asmolabs.zanshin.common.domain.crypto;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Every hash in Zanshin, computed in one place, by one provider.
 *
 * <p><b>Why BouncyCastle rather than {@code MessageDigest}.</b> The JCA picks an
 * implementation from whatever providers the JVM was started with, so the algorithm that
 * actually runs is a property of the deployment — a {@code java.security} edit, a FIPS
 * module, a vendor JDK. For a hash that decides whether an audit log has been tampered with,
 * "which implementation ran" should not depend on the host. BouncyCastle's lightweight API is
 * asked for {@link SHA256Digest} by name and gets it, on every machine.
 *
 * <p>It also keeps the algorithms enumerable: everything that hashes calls this class, so
 * answering "what do we hash with, and where" is a find-usages rather than an audit.
 *
 * <p>The lightweight API is used in preference to registering a JCA provider on purpose.
 * Registering one is global mutable state in a process that also runs a web server; calling
 * the engine directly has no such reach.
 */
public final class Digests {

    private Digests() {}

    /**
     * The separator for every composite hash in this system.
     *
     * <p>NUL, because it cannot occur in any value being hashed — not in a file path, not in a
     * package name, not in a user-supplied description. A printable separator can be imitated:
     * with a vertical bar, a path containing {@code |} shifts the field boundary, and two
     * different inputs collapse onto one hash.
     *
     * <p>The NestJS implementation used a bar for issue fingerprints and documented that it
     * must not be fixed, because changing it would have rewritten the identity of every issue
     * already stored and destroyed the triage attached to them. No data exists yet, so it is
     * fixed here — and this is the last moment at which it can be.
     */
    public static final char SEPARATOR = '\0';

    /**
     * How an instant is written when it is about to be hashed.
     *
     * <p>{@code appendInstant(3)} is ISO-8601, UTC, with the fraction fixed at three digits.
     * The width is the contract, not a display preference: {@code Instant::toString} drops the
     * fraction when it is zero and prints six or nine digits when the instant carries them, so
     * an entry landing exactly on the second would hash one way here and another way in a
     * process that always writes milliseconds. The alarm that followed would name integrity
     * when the cause was formatting.
     *
     * <p>Truncate before hashing rather than relying on this to round: a value with microsecond
     * precision hashes as its truncation while comparing unequal to it in memory, which is a
     * confusing way to discover the same problem.
     */
    private static final DateTimeFormatter CANONICAL_INSTANT =
            new DateTimeFormatterBuilder().appendInstant(3).toFormatter();

    /**
     * An instant's comparable form.
     *
     * <p>Always UTC, whatever the machine's timezone: two processes in two zones must produce
     * the same string for the same instant, or a hash computed here does not verify there.
     */
    public static String canonical(Instant value) {
        return CANONICAL_INSTANT.format(value);
    }

    /** SHA-256 of the UTF-8 bytes, lowercase hex. */
    public static String sha256Hex(String value) {
        return sha256Hex(value.getBytes(StandardCharsets.UTF_8));
    }

    public static String sha256Hex(byte[] value) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(value, 0, value.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return Hex.toHexString(out);
    }

    /**
     * Hashes an ordered list of fields, NUL-separated.
     *
     * <p>{@code null} and the empty string are deliberately indistinguishable: both mean "this
     * field has no value", and telling them apart would make the hash depend on how a driver
     * renders an empty column.
     */
    public static String sha256Fields(String... fields) {
        StringBuilder joined = new StringBuilder();
        for (int i = 0; i < fields.length; i++) {
            if (i > 0) {
                joined.append(SEPARATOR);
            }
            joined.append(fields[i] == null ? "" : fields[i]);
        }
        return sha256Hex(joined.toString());
    }
}
