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
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A ceiling per address on the inbound tracker webhook, the one anonymous route that writes.
 *
 * <p><b>What was missing.</b> {@code POST /api/v1/tickets/webhook/{provider}} needs no session —
 * the caller is the tracker — and sat outside {@link LoginRateLimitFilter}'s paths. Every call cost
 * a secret decryption, an HMAC and, when refused, a row in the hash-chained audit log, which is
 * never purged. An anonymous client could therefore write to that log as fast as it could send.
 * The refusals are now audited sparingly ({@code TicketingWebhookService}); this is the layer
 * underneath, which drops a flood before any of that work is done.
 *
 * <p><b>Its own bucket, not the sign-in one.</b> Sharing {@code LIMITED_PATHS} would put a
 * tracker's deliveries and a person's sign-ins in one allowance of ten a minute: a bulk transition
 * in Jira would lock the office behind the same egress out of its own control plane. The ceiling
 * here is generous for the same reason — a bulk edit of a few hundred tickets is a few hundred
 * deliveries in a minute, from one of the tracker's addresses — and configurable, because a
 * tracker behind a shared egress may need more. A refused delivery is lost unless the tracker
 * retries it, which is why the default errs high.
 *
 * <p>Bounded like the other limiters, for the reason {@link LoginRateLimitFilter} gives: the map of
 * addresses must not itself be the attack.
 */
@Component
public class WebhookRateLimitFilter extends OncePerRequestFilter {

    /** The routed prefix of the webhook, one route per provider below it. */
    static final String WEBHOOK_PREFIX = "/api/v1/tickets/webhook/";

    private static final int DEFAULT_CAPACITY = 300;
    private static final Duration DEFAULT_WINDOW = Duration.ofMinutes(1);
    private static final int MAX_ENTRIES = 10_000;

    private final Map<String, Bucket> buckets = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Bucket> eldest) {
                    return size() > MAX_ENTRIES;
                }
            });

    private final TrustedProxies proxies;
    private final int capacity;
    private final Duration window;

    public WebhookRateLimitFilter(
            TrustedProxies proxies,
            @Value("${vectispire.security.webhook-requests-per-window:300}") int capacity,
            @Value("${vectispire.security.webhook-request-window:PT1M}") Duration window) {
        this.proxies = proxies;
        // A ceiling of zero would refuse every delivery, so a misconfiguration falls back to the
        // shipped value rather than silently cutting the tracker off.
        this.capacity = capacity > 0 ? capacity : DEFAULT_CAPACITY;
        this.window = window != null && !window.isZero() && !window.isNegative() ? window : DEFAULT_WINDOW;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!isWebhook(request)) {
            chain.doFilter(request, response);
            return;
        }

        Bucket bucket = buckets.computeIfAbsent(proxies.clientAddress(request), address -> newBucket());
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        if (!probe.isConsumed()) {
            long retryAfter = Math.max(1, probe.getNanosToWaitForRefill() / 1_000_000_000L);
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfter));
            response.getWriter().write(
                    "{\"message\":\"Too many webhook deliveries from this address. Try again in %d seconds.\"}"
                            .formatted(retryAfter));
            return;
        }

        chain.doFilter(request, response);
    }

    /** Matched on the routed path, so an encoded spelling of the route cannot step around it. */
    private static boolean isWebhook(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod())
                && LoginRateLimitFilter.routedPath(request).startsWith(WEBHOOK_PREFIX);
    }

    private Bucket newBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder().capacity(capacity).refillGreedy(capacity, window).build())
                .build();
    }

    /** Clears the tracked addresses. For the tests. */
    public void reset() {
        buckets.clear();
    }
}
