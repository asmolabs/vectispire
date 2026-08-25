package com.asmolabs.vectispire.core.api.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

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
 * source, which for an Apache-2.0 project is every attacker. The header is now honoured only
 * when the <em>immediate</em> peer is a proxy named in {@code vectispire.security.trusted-proxies};
 * otherwise the peer's own address is the key, and a spoofed header changes nothing.
 *
 * <p>Empty configuration means "no proxy in front", which is the safe reading: a deployment
 * behind a load balancer that forgets to configure it rate-limits the balancer as one client —
 * visible immediately — rather than silently limiting nobody at all.
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
            "/api/v1/auth/session/exchange");

    private static final int MAX_IP_ENTRIES = 10_000;

    private static final int CAPACITY = 10;
    private static final Duration REFILL_PERIOD = Duration.ofMinutes(1);

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

    private final List<IpAddressMatcher> trustedProxies;

    public LoginRateLimitFilter(
            @Value("${vectispire.security.trusted-proxies:}") String configuredProxies) {
        this.trustedProxies = parseProxies(configuredProxies);
        if (this.trustedProxies.isEmpty()) {
            log.info("No trusted proxies configured — X-Forwarded-For is ignored and the peer "
                    + "address is the rate-limit key. Set vectispire.security.trusted-proxies "
                    + "when running behind a load balancer.");
        }
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (isLimited(request)) {
            String clientIp = resolveClientIp(request);
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
        return "POST".equalsIgnoreCase(request.getMethod())
                && LIMITED_PATHS.contains(request.getRequestURI());
    }

    /**
     * The peer's address, or what a proxy we trust says is behind it.
     *
     * <p>The rightmost entry a client cannot control is the correct one to take, and with a
     * single trusted hop that is the first: everything to its left was written by whoever called
     * the proxy. With several hops the leftmost untrusted entry is the honest answer, which is
     * what the walk below finds.
     */
    private String resolveClientIp(HttpServletRequest request) {
        String peer = request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();

        if (!isTrustedProxy(peer)) {
            return peer;
        }

        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) {
            return peer;
        }

        String[] hops = forwarded.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].trim();
            if (!hop.isEmpty() && !isTrustedProxy(hop)) {
                return hop;
            }
        }

        // Every hop claims to be a trusted proxy. Nothing here identifies a client, so the peer
        // is what is left — and it is a real address rather than a claimed one.
        return peer;
    }

    private boolean isTrustedProxy(String address) {
        for (IpAddressMatcher matcher : trustedProxies) {
            try {
                if (matcher.matches(address)) {
                    return true;
                }
            } catch (IllegalArgumentException malformed) {
                // A header value that is not an address matches nothing, which is the answer.
                return false;
            }
        }
        return false;
    }

    private static List<IpAddressMatcher> parseProxies(String configured) {
        if (configured == null || configured.isBlank()) {
            return List.of();
        }
        return java.util.Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(entry -> !entry.isEmpty())
                .map(IpAddressMatcher::new)
                .toList();
    }

    private Bucket createNewBucket() {
        Bandwidth limit = Bandwidth.builder()
                .capacity(CAPACITY)
                .refillGreedy(CAPACITY, REFILL_PERIOD)
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    /** Clears all tracked buckets (useful in unit tests). */
    public void reset() {
        buckets.clear();
    }
}
