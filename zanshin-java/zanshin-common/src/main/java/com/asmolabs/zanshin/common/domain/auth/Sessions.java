package com.asmolabs.zanshin.common.domain.auth;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A session's rules.
 *
 * <p>Three properties, and the design exists for them:
 *
 * <ol>
 *   <li><b>Revocable.</b> A session is an entry in a store; deleting it really does log the
 *       user out, including from another device.
 *   <li><b>Expiring.</b> An absolute lifetime bounds what a stolen token allows; an idle
 *       lifetime closes forgotten sessions.
 *   <li><b>Opaque.</b> The token carries no information — no JWT, so nothing to decode, nothing
 *       that ages badly, and revocation needs no blocklist.
 * </ol>
 */
public final class Sessions {

    private Sessions() {}

    /** 32 bytes of entropy: 43 characters in base64url, nothing to escape. */
    private static final int TOKEN_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Pattern BEARER = Pattern.compile("^Bearer (\\S+)$");

    /**
     * @param absoluteLifetime the ceiling, whatever happens
     * @param idleLifetime past this much silence the session closes even with lifetime left
     */
    public record Policy(Duration absoluteLifetime, Duration idleLifetime) {

        public static final Policy DEFAULT = new Policy(Duration.ofHours(12), Duration.ofMinutes(60));
    }

    /**
     * The two causes of closure are told apart because the operator tuning the durations needs
     * to know which one is actually closing their users' sessions.
     */
    public enum State {
        ACTIVE,
        EXPIRED,
        IDLE
    }

    public static String newToken() {
        byte[] material = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(material);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(material);
    }

    public static State stateOf(Instant createdAt, Instant lastSeenAt, Instant now, Policy policy) {
        if (!now.isBefore(createdAt.plus(policy.absoluteLifetime()))) {
            return State.EXPIRED;
        }
        if (!now.isBefore(lastSeenAt.plus(policy.idleLifetime()))) {
            return State.IDLE;
        }
        return State.ACTIVE;
    }

    public static boolean isActive(Instant createdAt, Instant lastSeenAt, Instant now, Policy policy) {
        return stateOf(createdAt, lastSeenAt, now, policy) == State.ACTIVE;
    }

    /**
     * Extracts the token from an {@code Authorization} header.
     *
     * <p>Empty for anything that is not exactly {@code Bearer <token>}. Telling "absent",
     * "malformed" and "unknown" apart would inform somebody probing, without helping anybody
     * else.
     */
    public static Optional<String> bearerToken(String header) {
        if (header == null || header.isBlank()) {
            return Optional.empty();
        }
        Matcher match = BEARER.matcher(header.trim());
        return match.matches() ? Optional.of(match.group(1)) : Optional.empty();
    }
}
