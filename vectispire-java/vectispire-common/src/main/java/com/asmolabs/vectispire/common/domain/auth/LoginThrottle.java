package com.asmolabs.vectispire.common.domain.auth;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import java.text.Normalizer;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

/**
 * Throttling of login attempts.
 *
 * <p><b>Three counters, and all have to pass.</b> This is not redundancy — each one alone has a
 * hole another closes:
 *
 * <ul>
 *   <li>An <b>account from one client</b> — {@link #MAX_ATTEMPTS_PER_USER}: the owner's mistypes,
 *       and a guesser working from one place.
 *   <li>An <b>account from everywhere</b> — {@link #MAX_ATTEMPTS_PER_ACCOUNT}, ten times higher:
 *       a guesser spread across many machines tries no more than that against one account.
 *   <li>A <b>client</b> across every account — {@link #MAX_ATTEMPTS_PER_CLIENT}: one password
 *       tried across many names.
 * </ul>
 *
 * <p><b>The account's low ceiling used to be shared by every client.</b> Five wrong passwords a
 * quarter of an hour, from anywhere, kept any account whose name was known locked — the governor's
 * included — and its owner, typing the right password from their own workstation, was refused with
 * the rest. Keyed per client, the same five lock out only the client that sent them; locking the
 * owner out takes the global ceiling, ten times higher and from at least ten clients, which is
 * exactly the distributed guessing it exists to stop.
 *
 * <p>A shared workstation can legitimately watch several people mistype; an account cannot.
 *
 * <p><b>The window slides rather than being fixed.</b> A fixed window resets on the hour, which
 * hands an attacker a free burst at the boundary.
 *
 * <p>The check happens <b>before</b> any password comparison: a locked account must cost no
 * hashing rounds, or the throttle itself becomes the lever for a denial of service.
 */
public final class LoginThrottle {

    private LoginThrottle() {}

    /** Failures against one account, or one typed name, from one client. */
    public static final int MAX_ATTEMPTS_PER_USER = 5;
    /** Failures against one account, or one typed name, whatever the client. */
    public static final int MAX_ATTEMPTS_PER_ACCOUNT = 50;
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
     * The key under which the failures against a typed name are counted — for an account that
     * exists as well as for one that does not.
     *
     * <p>Folded, or "Alice", "alice" and "alice  " are three counters and the threshold is worth
     * three times as much to anyone bothering to vary the case. <b>Accents are folded too</b>
     * (compatibility decomposition, marks dropped, lower-cased in the root locale), and the key is
     * counted for existing accounts beside {@link #accountKey}: the database's collation decides
     * which spellings open an account — case on MySQL and not on PostgreSQL, accents on MySQL — so
     * a counter keyed on the account alone locked "Àlice" when the account existed and not when it
     * did not, and the lockout answered the question the uniform 401 refuses to.
     */
    public static String userKey(String username) {
        String folded = Normalizer.normalize(username.trim(), Normalizer.Form.NFKD).replaceAll("\\p{M}", "");
        // Upper then lower: `ß` and `ẞ` become `ss`, which lower-casing alone leaves as they are.
        String lower = folded.toUpperCase(Locale.ROOT).toLowerCase(Locale.ROOT);
        StringBuilder key = new StringBuilder(lower.length());
        lower.codePoints().forEach(c -> key.append(COLLATION_LETTERS.getOrDefault(c, Character.toString(c))));
        return "login:user:" + key;
    }

    /**
     * The letters MySQL's {@code utf8mb4_0900_ai_ci} equates with others, which a compatibility
     * decomposition does not take apart.
     *
     * <p><b>Measured on the server, not recalled.</b> The fold above left them alone, and the
     * collation did not: {@code jeßica} opened {@code jessica} while counting against a counter of its
     * own, so five failures as {@code jessica} and one more as {@code jeßica} answered 429 when the
     * account existed and 401 when it did not — the oracle this key exists to close (the audit of 10
     * October 2026). {@code CollationFoldDatabaseTest} asks the server about each of them, so the
     * list cannot drift from the collation the installation actually runs.
     */
    static final java.util.Map<Integer, String> COLLATION_LETTERS = java.util.Map.of(
            (int) 'æ', "ae", (int) 'œ', "oe", (int) 'ø', "o", (int) 'ł', "l", (int) 'đ', "d",
            (int) 'ð', "d", (int) 'ħ', "h", (int) 'ŀ', "l", (int) '·', "");

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

    /** The account's failures from one client — see {@link #MAX_ATTEMPTS_PER_USER}. */
    public static String accountKey(long accountId, String clientId) {
        return fromClient(accountKey(accountId), clientId);
    }

    /**
     * The typed name's failures from one client, beside {@link #accountKey(long, String)} for the
     * same reason {@link #userKey(String)} sits beside {@link #accountKey(long)}: which counters an
     * attempt meets must not depend on whether the account exists.
     */
    public static String userKey(String username, String clientId) {
        return fromClient(userKey(username), clientId);
    }

    /**
     * A counter narrowed to one client bucket, as a digest: the typed name is the caller's and has
     * no length the column knows, and the bucket adds to it.
     */
    private static String fromClient(String key, String clientId) {
        return "login:from-client:" + Digests.sha256Fields(key, ClientBuckets.of(clientId));
    }

    /** Wrong second-factor codes, per account — see {@link #MAX_SECOND_FACTOR_FAILURES}. */
    public static String secondFactorKey(long accountId) {
        return "login:mfa:" + accountId;
    }

    /**
     * Namespaced apart from {@link #userKey}, so a client id cannot borrow a user's budget. An IPv6
     * client counts on its /64, see {@link ClientBuckets}.
     */
    public static String clientKey(String clientId) {
        return "login:client:" + ClientBuckets.of(clientId);
    }
}
