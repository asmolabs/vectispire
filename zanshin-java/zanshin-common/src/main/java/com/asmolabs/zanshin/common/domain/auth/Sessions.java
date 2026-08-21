package com.asmolabs.zanshin.common.domain.auth;

import com.asmolabs.zanshin.common.domain.crypto.Digests;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.util.Arrays;

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
 *   <li><b>Not stored.</b> What the store holds is the token's SHA-256, never the token. A
 *       database dump — a backup, a read-only replica, a {@code select *} in a support
 *       session — therefore hands over no live session. See {@link #issue()}.
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

    public record Session(
            String token,
            long userId,
            String username,
            String role,
            Instant createdAt,
            Instant lastSeenAt,
            /* The account must change its password before reaching anything else. */
            boolean mustChangePassword) {}

    /**
     * The two causes of closure are told apart because the operator tuning the durations needs
     * to know which one is actually closing their users' sessions.
     */
    public enum State {
        ACTIVE,
        EXPIRED,
        IDLE
    }

    /**
     * A token as it is handed out, and as it is stored.
     *
     * <p>Two fields rather than one, because they are two different secrets' worth: {@code token}
     * goes to the client and is never written down, {@code hash} is written down and cannot be
     * turned back into {@code token}. Returning them together is what makes it impossible to
     * store the wrong one by accident — there is no method that produces a token alone.
     */
    public record IssuedToken(String token, String hash) {}

    /**
     * Mints a session token: the caller sends {@link IssuedToken#token()} to the client and
     * stores {@link IssuedToken#hash()}.
     *
     * <p><b>SHA-256 and not Argon2id, deliberately, and the reasoning is the opposite of the
     * password one.</b> A password is low-entropy and guessable, so the defence is to make each
     * guess expensive. This token is 32 bytes from {@link SecureRandom}: there is no dictionary
     * to walk and no guess to slow down, so a memory-hard derivation would buy nothing — and it
     * would be paid on <b>every authenticated request</b>, which is how a protection becomes a
     * denial-of-service lever. API keys can afford Argon2 precisely because their stored prefix
     * narrows the lookup to a handful of rows first; a session is resolved by primary key, once
     * per request, and has no such budget.
     *
     * <p>What the hash does buy is the only property at stake here: whoever reads the table
     * reads verifiers, not credentials.
     */
    public static IssuedToken issue() {
        byte[] material = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(material);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(material);
        return new IssuedToken(token, hashOf(token));
    }

    /**
     * The stored form of a token somebody just presented.
     *
     * <p>The lookup that follows is an equality on the primary key, which is not a constant-time
     * comparison — and does not need to be. What the engine compares is the hash of what the
     * caller sent; learning how many of its bytes matched reveals a prefix of a SHA-256 that the
     * caller already knows in full, and says nothing about any other session's token.
     */
    public static String hashOf(String presented) {
        return Digests.sha256Hex(presented);
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
     * Compares two tokens in constant time.
     *
     * <p>An ordinary comparison stops at the first differing byte, and its duration reveals how
     * many bytes were already right. Hardly exploitable across a network, and closing the door
     * costs one method call.
     */
    public static boolean tokensMatch(String candidate, String expected) {
        if (candidate == null || expected == null) {
            return false;
        }
        return Arrays.constantTimeAreEqual(
                candidate.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
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
