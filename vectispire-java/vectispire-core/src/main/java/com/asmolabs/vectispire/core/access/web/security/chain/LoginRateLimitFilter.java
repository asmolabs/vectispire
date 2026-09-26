package com.asmolabs.vectispire.core.access.web.security.chain;

import com.asmolabs.vectispire.core.access.web.security.TrustedProxies;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriUtils;

/**
 * Token-Bucket rate limiter for the anonymous half of {@code /api/v1/auth}.
 *
 * <p><b>Primary, zero-cost HTTP defence.</b> It runs before any controller method, database
 * query or Argon2id derivation, so a burst is dropped before it costs anything worth spending.
 *
 * <h2>The header is not the client, unless a proxy we run says it is</h2>
 *
 * <p>This filter used to read the first element of {@code X-Forwarded-For} whenever the header
 * was present. Anyone could therefore send a different value on every request and receive a
 * fresh bucket each time — the limit was a formality against an attacker who had read the
 * source, which for an Apache-2.0 project is every attacker.
 *
 * <p>That rule now lives in {@link TrustedProxies}, because it is the same question
 * {@code X-Forwarded-Proto} asks on the agent protocol and the two answers had drifted apart.
 * See that class for what an empty configuration means.
 *
 * <h2>Bounded, and pruned where it fills</h2>
 *
 * <p>Eviction used to run only on the rejection path, which is exactly the path a
 * header-rotating attacker never takes: every request looked like a new client, was admitted,
 * and left an entry behind. The map is now a bounded LRU that drops its least-recently-used
 * entry on insertion, so the memory is capped by construction rather than by a reaction.
 *
 * <p>Dropping the least-recently-used bucket does hand back an early refill to whoever owns it.
 * That is the standard cost of a fixed-size limiter, and it is bounded by the size below: an
 * attacker has to push ten thousand <em>other</em> live clients out of the map to buy one extra
 * attempt, which is more expensive than the attempt is worth.
 */
@Component
public class LoginRateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(LoginRateLimitFilter.class);

    /**
     * **Every anonymous door, not just the first one.**
     *
     * <p>Limiting {@code /login} alone left {@code /mfa/verify} — the six-digit second factor —
     * with no ceiling at all. The challenge now dies after three wrong codes, and this is the
     * layer underneath: it applies to the anonymous routes as a group, so a route added to that
     * group later inherits it instead of having to remember it.
     */
    private static final Set<String> LIMITED_PATHS = Set.of(
            "/api/v1/auth/login",
            "/api/v1/auth/mfa/verify",
            "/api/v1/auth/session/exchange",
            // Not anonymous, and limited all the same: it verifies a second-factor code, so a
            // session left open is a door to the same six digits. The account's budget bounds the
            // guesses; this bounds how fast one address can spend it.
            "/api/v1/auth/mfa/disable",
            // The same for a password: a session is not a licence to guess the one behind it.
            "/api/v1/auth/change-password");

    private static final int MAX_IP_ENTRIES = 10_000;

    /**
     * Ten sign-in attempts a minute from one address, and <b>configurable because one address is
     * not always one person.</b>
     *
     * <p>The default is deliberately tight: it is the ceiling that makes credential stuffing
     * expensive, and it is right for a deployment whose users arrive from their own addresses.
     * It is wrong for two real situations, and neither is hypothetical — an office behind a
     * single NAT egress, where the whole floor shares one key, and a browser test suite, where
     * eleven sign-ins in a minute is the suite rather than an attack.
     *
     * <p>Raising it is a decision an operator takes with their eyes open, which is why it is a
     * setting and not a heuristic that quietly widens itself for private address ranges. The
     * account-level throttle in {@code LoginThrottle} — five attempts per user — is unaffected
     * by this and keeps guarding the case this one cannot see.
     */
    private static final int DEFAULT_CAPACITY = 10;
    private static final Duration DEFAULT_REFILL_PERIOD = Duration.ofMinutes(1);

    /**
     * Access-ordered and size-bounded: {@code removeEldestEntry} makes insertion the moment the
     * pruning happens, which is the path every request takes.
     *
     * <p>Wrapped rather than concurrent because {@code LinkedHashMap}'s access order mutates the
     * structure on a <em>read</em>, so a lock-free map cannot express it. The critical section
     * is a hash lookup on a request that is about to hash a password; it is not the bottleneck.
     */
    private final Map<String, Bucket> buckets = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Bucket> eldest) {
                    return size() > MAX_IP_ENTRIES;
                }
            });

    private final TrustedProxies proxies;
    private final int capacity;
    private final Duration refillPeriod;

    /** The shipped ceiling, for a caller with no opinion — the tests, and nothing else. */
    public LoginRateLimitFilter(String configuredProxies) {
        this(new TrustedProxies(configuredProxies), DEFAULT_CAPACITY, DEFAULT_REFILL_PERIOD);
    }

    @Autowired
    public LoginRateLimitFilter(
            TrustedProxies proxies,
            @Value("${vectispire.security.login-attempts-per-window:10}") int capacity,
            @Value("${vectispire.security.login-attempt-window:PT1M}") Duration refillPeriod) {

        // A ceiling of zero would refuse every sign-in including the operator's, so a
        // misconfiguration falls back to the shipped value rather than locking the deployment out
        // of itself.
        this.capacity = capacity > 0 ? capacity : DEFAULT_CAPACITY;
        this.refillPeriod = refillPeriod != null && !refillPeriod.isZero() && !refillPeriod.isNegative()
                ? refillPeriod
                : DEFAULT_REFILL_PERIOD;
        if (this.capacity != DEFAULT_CAPACITY || !this.refillPeriod.equals(DEFAULT_REFILL_PERIOD)) {
            log.info("Sign-in rate limit set to {} attempts per {} per address (default is {} per {}).",
                    this.capacity, this.refillPeriod, DEFAULT_CAPACITY, DEFAULT_REFILL_PERIOD);
        }
        this.proxies = proxies;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (isLimited(request)) {
            String clientIp = proxies.clientAddress(request);
            Bucket bucket = buckets.computeIfAbsent(clientIp, k -> createNewBucket());

            ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
            if (!probe.isConsumed()) {
                long retryAfterSeconds = Math.max(1, probe.getNanosToWaitForRefill() / 1_000_000_000L);

                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
                response.setHeader("X-Rate-Limit-Retry-After-Seconds", String.valueOf(retryAfterSeconds));
                response.getWriter().write("""
                        {"message":"Rate limit exceeded. Too many login attempts. Please try again in %d seconds."}
                        """.formatted(retryAfterSeconds).trim());
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isLimited(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod()) && LIMITED_PATHS.contains(routedPath(request));
    }

    /**
     * The path as the dispatcher will route it, not as the client spelled it.
     *
     * <p>The raw URI used to be compared, and the dispatcher decodes before it matches: a POST to
     * {@code /api/v1/auth/%6Cogin} reached the login endpoint and skipped this limiter entirely,
     * one percent sign being the whole cost. So the comparison is made on what the routing sees
     * — decoded, without the context path, without {@code ;} parameters, empty segments or a
     * trailing slash. Normalizing more than the dispatcher does only limits a request that would
     * have answered 404; normalizing less is the bypass.
     */
    static String routedPath(HttpServletRequest request) {
        String path = request.getRequestURI() == null ? "" : request.getRequestURI();
        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && path.startsWith(context)) {
            path = path.substring(context.length());
        }
        StringBuilder routed = new StringBuilder();
        for (String segment : path.split("/")) {
            int parameters = segment.indexOf(';');
            String name = UriUtils.decode(parameters >= 0 ? segment.substring(0, parameters) : segment, StandardCharsets.UTF_8);
            if (!name.isEmpty()) {
                routed.append('/').append(name);
            }
        }
        return routed.toString();
    }

    private Bucket createNewBucket() {
        Bandwidth limit = Bandwidth.builder()
                .capacity(capacity)
                .refillGreedy(capacity, refillPeriod)
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    /** Clears all tracked buckets (useful in unit tests). */
    public void reset() {
        buckets.clear();
    }
}
