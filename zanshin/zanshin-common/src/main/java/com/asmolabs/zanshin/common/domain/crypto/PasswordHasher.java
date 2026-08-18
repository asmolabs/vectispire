package com.asmolabs.zanshin.common.domain.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;

/**
 * Password hashing: Argon2id, through BouncyCastle.
 *
 * <p><b>Argon2id rather than bcrypt.</b> The NestJS implementation used bcrypt because it had
 * to read hashes written by a Python one; nothing is stored yet, so the constraint is gone and
 * with it the defect it dragged along — <b>bcrypt silently ignores everything past 72
 * bytes</b>. That forced a validation rule refusing longer passwords, because accepting them
 * would have let someone believe a 90-character passphrase protected them when a third of it
 * was never hashed. Argon2 has no such limit, so the rule is gone too.
 *
 * <p>Argon2id specifically: it resists both the GPU attack Argon2i is weak to and the
 * side-channel attack Argon2d is weak to, which is why it is the variant every current
 * guideline names.
 *
 * <p>The parameters below follow OWASP's recommendation — 19 MiB of memory, two passes. The
 * memory cost is the point: it is what makes a rack of GPUs no better at this than a laptop,
 * and it is the parameter that has no equivalent in bcrypt.
 *
 * <h2>The encoded form</h2>
 *
 * <p>{@code $argon2id$v=19$m=…,t=…,p=…$salt$hash}, the PHC string format. Parameters travel
 * with the hash, so raising the cost later does not invalidate what is already stored: an old
 * hash still verifies under its own parameters, and can be rewritten on the next successful
 * login.
 */
public final class PasswordHasher {

    private PasswordHasher() {}

    /** 19 MiB, in kibibytes. */
    private static final int MEMORY_KIB = 19 * 1024;

    private static final int ITERATIONS = 2;
    private static final int PARALLELISM = 1;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getDecoder();

    public static String hash(String password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] digest = derive(password, salt, MEMORY_KIB, ITERATIONS, PARALLELISM);

        return "$argon2id$v=" + Argon2Parameters.ARGON2_VERSION_13
                + "$m=" + MEMORY_KIB + ",t=" + ITERATIONS + ",p=" + PARALLELISM
                + "$" + ENCODER.encodeToString(salt)
                + "$" + ENCODER.encodeToString(digest);
    }

    /**
     * Verifies a password against a stored hash.
     *
     * <p>Returns {@code false} for a malformed or absent hash rather than throwing. A row with a
     * corrupt hash must fail authentication, not take down the login endpoint — and an attacker
     * must not be able to tell the two apart.
     */
    public static boolean verify(String password, String encoded) {
        if (password == null || encoded == null || encoded.isBlank()) {
            return false;
        }

        String[] parts = encoded.split("\\$");
        // ["", "argon2id", "v=19", "m=…,t=…,p=…", salt, hash]
        if (parts.length != 6 || !"argon2id".equals(parts[1])) {
            return false;
        }

        try {
            int memory = intParameter(parts[3], "m=");
            int iterations = intParameter(parts[3], "t=");
            int parallelism = intParameter(parts[3], "p=");
            byte[] salt = DECODER.decode(parts[4]);
            byte[] expected = DECODER.decode(parts[5]);

            byte[] actual = derive(password, salt, memory, iterations, parallelism);
            // Constant time: an ordinary comparison stops at the first differing byte, and its
            // duration is a measurement of how much of the hash was right.
            return Arrays.constantTimeAreEqual(expected, actual);
        } catch (IllegalArgumentException malformed) {
            return false;
        }
    }

    /**
     * Whether a stored hash was produced with weaker parameters than the current ones.
     *
     * <p>Costs are raised as hardware gets faster, and a hash written five years ago stays
     * exactly as weak as the day it was written unless something notices. The caller has the one
     * moment when rewriting is possible: a successful login, when the plaintext is in hand.
     */
    public static boolean needsRehash(String encoded) {
        if (encoded == null || !encoded.startsWith("$argon2id$")) {
            return true;
        }
        String[] parts = encoded.split("\\$");
        if (parts.length != 6) {
            return true;
        }
        try {
            return intParameter(parts[3], "m=") < MEMORY_KIB || intParameter(parts[3], "t=") < ITERATIONS;
        } catch (IllegalArgumentException malformed) {
            return true;
        }
    }

    private static byte[] derive(String password, byte[] salt, int memoryKib, int iterations, int parallelism) {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(memoryKib)
                .withIterations(iterations)
                .withParallelism(parallelism)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);

        byte[] digest = new byte[HASH_BYTES];
        generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), digest);
        return digest;
    }

    private static int intParameter(String parameters, String name) {
        for (String parameter : parameters.split(",")) {
            if (parameter.startsWith(name)) {
                return Integer.parseInt(parameter.substring(name.length()));
            }
        }
        throw new IllegalArgumentException("missing parameter " + name);
    }
}
