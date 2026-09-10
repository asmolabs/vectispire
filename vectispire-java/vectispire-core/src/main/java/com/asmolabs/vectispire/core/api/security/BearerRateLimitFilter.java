package com.asmolabs.vectispire.core.api.security;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.services.AuditLogService;
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
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A ceiling on <b>refused</b> bearer tokens, which the password had and the keys did not.
 *
 * <h2>What was missing</h2>
 *
 * <p>{@link LoginRateLimitFilter} makes credential stuffing expensive on {@code /auth/login}, and
 * {@code LoginThrottle} does it again per account. Everything else authenticates by presenting a
 * token to {@link BearerAuthenticationFilter} — a session token, an <b>agent API key</b>, a SCIM
 * provisioning token — and none of those had any ceiling at all.
 *
 * <p><b>The real gap was not guessing, it was silence.</b> These tokens are long and random, so
 * walking the space is not the threat; a sweep leaving no distinguishable trace is. A refused
 * bearer produced a 401 in an access log and nothing in the audit log, so a machine trying keys
 * for a week looked exactly like a misconfigured agent retrying. This filter puts a number on it
 * and writes one entry when the number is reached.
 *
 * <h2>Only failures are counted, and only credentialed requests</h2>
 *
 * <p>A request with no {@code Authorization} header is not a credential attempt — the sign-in
 * page, the SPA's own assets and the published badge are all of that shape, and counting them
 * would rate-limit reading. A request whose token <em>worked</em> is not one either: a busy agent
 * long-polling every thirty seconds must never be throttled by a filter meant for somebody
 * guessing, and an interface making twenty calls to paint a page even less.
 *
 * <p>So the count is taken <b>after</b> the chain has run, by asking whether anything ended up in
 * the security context. That is one boolean read on the way out, on the requests that carried a
 * token, and it is what makes the limit fall exactly on the population it is aimed at.
 *
 * <h2>The refusal is generous, deliberately</h2>
 *
 * <p>Sixty failures in five minutes from one address is far above what a working deployment
 * produces and far below what a sweep needs. It has to leave room for the ordinary accidents —
 * an agent started with a stale key retrying its loop, a browser tab left open across a session
 * expiry, a CI job holding a revoked key — because the cost of a false positive here is an
 * operator locked out of their own control plane, and the value of the control is mostly the
 * audit entry rather than the refusal.
 */
@Component
public class BearerRateLimitFilter extends OncePerRequestFilter {

    private static final int DEFAULT_CAPACITY = 60;
    private static final Duration DEFAULT_WINDOW = Duration.ofMinutes(5);

    /** Bounded for the reason {@link LoginRateLimitFilter} gives: the map must not be the attack. */
    private static final int MAX_ENTRIES = 10_000;

    private final Map<String, Bucket> buckets = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Bucket> eldest) {
                    return size() > MAX_ENTRIES;
                }
            });

    private final TrustedProxies proxies;
    private final AuditLogService audit;
    private final int capacity;
    private final Duration window;

    public BearerRateLimitFilter(
            TrustedProxies proxies,
            AuditLogService audit,
            @Value("${vectispire.security.bearer-failures-per-window:60}") int capacity,
            @Value("${vectispire.security.bearer-failure-window:PT5M}") Duration window) {

        this.proxies = proxies;
        this.audit = audit;
        this.capacity = capacity > 0 ? capacity : DEFAULT_CAPACITY;
        this.window = window != null && !window.isZero() && !window.isNegative() ? window : DEFAULT_WINDOW;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!carriesBearer(request)) {
            chain.doFilter(request, response);
            return;
        }

        String client = proxies.clientAddress(request);
        Bucket bucket = buckets.get(client);

        // **Read without creating.** A bucket appears the first time an address fails, so an
        // estate of well-configured agents leaves this map empty and pays one hash lookup.
        if (bucket != null && bucket.getAvailableTokens() <= 0) {
            refuse(response, bucket);
            return;
        }

        chain.doFilter(request, response);

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            countFailure(client, request);
        }
    }

    /**
     * One audit entry per window, written on the failure that empties the bucket.
     *
     * <p>Not on every refusal afterwards: a loop retrying every second would write a thousand
     * identical rows into a log that is never purged, and the one entry that mattered would be
     * buried in its own alarm.
     */
    private void countFailure(String client, HttpServletRequest request) {
        Bucket bucket = buckets.computeIfAbsent(client, key -> newBucket());
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        if (probe.isConsumed() && probe.getRemainingTokens() == 0) {
            audit.record(new AuditLogService.Record(
                    AuditOperation.ACCESS_DENIED,
                    request.getRequestURI(),
                    capacity + " bearer tokens refused from this address within " + window
                            + ". Further credentialed requests from it are answered 429 until the window refills.",
                    null,
                    client,
                    request.getHeader(HttpHeaders.USER_AGENT)));
        }
    }

    private void refuse(HttpServletResponse response, Bucket bucket) throws IOException {
        long retryAfter = Math.max(1, secondsUntilRefill(bucket));
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfter));
        response.getWriter().write(
                "{\"message\":\"Too many refused credentials from this address. Try again in %d seconds.\"}"
                        .formatted(retryAfter));
    }

    private long secondsUntilRefill(Bucket bucket) {
        return bucket.estimateAbilityToConsume(1).getNanosToWaitForRefill() / 1_000_000_000L;
    }

    private static boolean carriesBearer(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        return header != null && header.regionMatches(true, 0, "bearer ", 0, 7);
    }

    private Bucket newBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder().capacity(capacity).refillGreedy(capacity, window).build())
                .build();
    }

    /** Clears the tracked addresses. For the tests, and for an operator who fixed the cause. */
    public void reset() {
        buckets.clear();
    }
}
