package com.asmolabs.vectispire.common.domain.apikeys;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.security.SecureRandom;
import java.time.Period;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Issuing an API key: {@code zsk_<43 characters>}, shown once.
 *
 * <p>Only the hash is stored. {@code prefix} keeps the first twelve characters <b>in the
 * clear</b> — it is not a secret, and it is what lets a request narrow the candidates before
 * hashing. Without it, every key-authenticated request would cost one password hash per
 * existing key: a denial of service handed to anyone who presents anything at all. With
 * Argon2's memory cost that is worse than it was under bcrypt, not better.
 *
 * <p><b>One validation from the original is missing on purpose.</b> It took a target kind and an
 * identifier as two loose values and had to refuse <em>half</em> a restriction — which would
 * have looked like a bounded key without being one. A key now carries an
 * {@link ScanTarget}, or carries nothing; the half cannot be written, so the check that caught
 * it has nothing left to catch.
 */
public final class ApiKeys {

    private ApiKeys() {}

    public static final String KEY_PREFIX = "zsk";

    /** {@code zsk_} plus eight characters: enough to select a handful of rows, not enough to help. */
    public static final int PREFIX_LENGTH = KEY_PREFIX.length() + 9;

    private static final int SECRET_BYTES = 32;
    private static final int MAX_LIFETIME_DAYS = 3650;

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * @param fullKey shown once and never stored
     * @param prefix stored in the clear, to narrow the lookup
     */
    public record IssuedKey(String fullKey, String prefix) {}

    public static IssuedKey generate() {
        byte[] secret = new byte[SECRET_BYTES];
        RANDOM.nextBytes(secret);
        String fullKey = KEY_PREFIX + "_" + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
        return new IssuedKey(fullKey, fullKey.substring(0, PREFIX_LENGTH));
    }

    /**
     * Normalizes a requested scope set, or explains the refusal.
     *
     * <p>Emitted in declaration order, so two keys granted the same scopes store the same
     * string — otherwise "does this key have the same rights as that one" becomes a set
     * comparison nobody remembers to write.
     */
    public static List<ApiKeyScope> normalizeScopes(Collection<String> requested) {
        if (requested == null || requested.isEmpty()) {
            return ApiKeyScope.defaults();
        }

        List<String> cleaned = requested.stream().filter(s -> s != null && !s.isBlank()).map(String::trim).toList();
        if (cleaned.isEmpty()) {
            throw new InvalidApiKeyException("A key with no scope at all could do nothing.");
        }

        List<String> unknown = new ArrayList<>();
        List<ApiKeyScope> granted = new ArrayList<>();
        for (String candidate : cleaned) {
            ApiKeyScope.fromWireName(candidate).ifPresentOrElse(granted::add, () -> unknown.add(candidate));
        }
        // Refused rather than ignored: a caller who misspells `agent` and gets a working key
        // will believe the scope was granted.
        if (!unknown.isEmpty()) {
            throw new InvalidApiKeyException("Unknown scope(s): " + String.join(", ", unknown));
        }

        return java.util.Arrays.stream(ApiKeyScope.values()).filter(granted::contains).toList();
    }

    /** A lifetime in days, or empty for a key that does not expire. */
    public static Optional<Period> normalizeLifetime(Integer expiresInDays) {
        if (expiresInDays == null) {
            return Optional.empty();
        }
        if (expiresInDays < 1 || expiresInDays > MAX_LIFETIME_DAYS) {
            throw new InvalidApiKeyException(
                    "Invalid lifetime: a number of days between 1 and " + MAX_LIFETIME_DAYS + ", or nothing.");
        }
        return Optional.of(Period.ofDays(expiresInDays));
    }
}
