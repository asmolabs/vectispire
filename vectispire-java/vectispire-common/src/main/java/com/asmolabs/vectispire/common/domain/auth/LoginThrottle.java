package com.asmolabs.vectispire.common.domain.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

/**
 * Throttling of login attempts.
 *
 * <p><b>Two independent counters, and both have to pass.</b> This is not redundancy — each
 * one alone has a hole the other closes:
 *
 * <ul>
 *   <li>Count per <b>user</b> only, and anybody can lock a colleague's account whose username
 *       they know: a denial of service at a third of the cost of an attack.
 *   <li>Count per <b>client</b> only, and an attacker spread across several machines tries as
 *       many passwords as they like against one account.
 * </ul>
 *
 * <p>Hence two thresholds rather than one. A shared workstation can legitimately watch several
 * people mistype; an account cannot.
 *
 * <p><b>The window slides rather than being fixed.</b> A fixed window resets on the hour, which
 * hands an attacker a free burst at the boundary.
 *
 * <p>The check happens <b>before</b> any password comparison: a locked account must cost no
 * hashing rounds, or the throttle itself becomes the lever for a denial of service.
 */
public final class LoginThrottle {

    private LoginThrottle() {}

    public static final int MAX_ATTEMPTS_PER_USER = 5;
    public static final int MAX_ATTEMPTS_PER_CLIENT = 20;
    public static final Duration WINDOW = Duration.ofMinutes(15);

    /**
     * Wrong second-factor codes an account may absorb per window, <b>across challenges</b>.
     *
     * <p>A challenge dies after three wrong codes, and that alone bounded nothing: whoever holds
     * the password signs in again, the password success clears the password counters, and the
     * next challenge brings three fresh guesses — a million-code space explored three at a time
     * for as long as the address limiter allows. This counter belongs to the account, survives
     * the password, and is cleared only by a right code. Only someone who already has the
     * password can spend it, so the lockout it causes is one the owner has reason to hear about.
     */
    public static final int MAX_SECOND_FACTOR_FAILURES = 5;

    /**
     * @param retryAfter how long to wait before another attempt; {@link Duration#ZERO} when
     *     allowed
     */
    public record Decision(boolean allowed, Duration retryAfter) {}

    /**
     * @param user the instants of this user's failures
     * @param client the same for this client
     */
    public record Attempts(List<Instant> user, List<Instant> client) {}

    /**
     * Decides whether an attempt is allowed, and if not for how much longer.
     *
     * <p>The delay is computed from the <b>oldest failure still inside the window</b> — the
     * instant at which the counter drops back below the threshold. The most constraining of the
     * two counters wins.
     */
    public static Decision decide(Attempts attempts, Instant now) {
        Duration user = waitFor(attempts.user(), MAX_ATTEMPTS_PER_USER, now);
        Duration client = waitFor(attempts.client(), MAX_ATTEMPTS_PER_CLIENT, now);

        Duration retryAfter = user.compareTo(client) >= 0 ? user : client;
        return new Decision(retryAfter.isZero(), retryAfter);
    }

    /** The same decision for one counter alone, against its own limit. */
    public static Decision decide(List<Instant> attempts, int limit, Instant now) {
        Duration retryAfter = waitFor(attempts, limit, now);
        return new Decision(retryAfter.isZero(), retryAfter);
    }

    private static Duration waitFor(List<Instant> attempts, int limit, Instant now) {
        List<Instant> inWindow = withinWindow(attempts, now);
        if (inWindow.size() < limit) {
            return Duration.ZERO;
        }

        Instant earliest = inWindow.stream().min(Instant::compareTo).orElseThrow();
        Duration remaining = Duration.between(now, earliest.plus(WINDOW));
        // At least one second. Announcing zero to a caller that is still blocked makes it retry
        // immediately and fail again, which is the throttle telling a lie about itself.
        return remaining.compareTo(Duration.ofSeconds(1)) < 0 ? Duration.ofSeconds(1) : remaining;
    }

    /** Keeps only the attempts still inside the window. */
    public static List<Instant> withinWindow(List<Instant> attempts, Instant now) {
        Instant cutoff = now.minus(WINDOW);
        return attempts.stream().filter(cutoff::isBefore).toList();
    }

    /**
     * The key under which a user's failures are counted.
     *
     * <p>Normalized, or "Alice", "alice" and "alice  " are three counters and the threshold is
     * worth three times as much to anyone bothering to vary the case.
     */
    public static String userKey(String username) {
        return "login:user:" + username.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * The key for an account that exists, which is the one that counts.
     *
     * <p>{@link #userKey} normalizes case, but the database's collation decides which spellings
     * open the account — on MySQL, accents too — and no normalization here can agree with every
     * collation. Keying on the id makes every spelling that reaches the account share its budget.
     */
    public static String accountKey(long accountId) {
        return "login:account:" + accountId;
    }

    /** Wrong second-factor codes, per account — see {@link #MAX_SECOND_FACTOR_FAILURES}. */
    public static String secondFactorKey(long accountId) {
        return "login:mfa:" + accountId;
    }

    /** Namespaced apart from {@link #userKey}, so a client id cannot borrow a user's budget. */
    public static String clientKey(String clientId) {
        return "login:client:" + clientId;
    }
}
