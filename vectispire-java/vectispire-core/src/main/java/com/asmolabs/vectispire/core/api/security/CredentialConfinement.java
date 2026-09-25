package com.asmolabs.vectispire.core.api.security;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.services.ApiKeyAuthService;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Keeps a credential that is not a session on the routes that declare it (decision 0024).
 *
 * <p><b>The role markers could not do it.</b> {@code @RequiresAccount} checks that the caller is
 * authenticated, and an agent key is authenticated: nothing kept an agent's key off the account
 * routes, where it saw an empty visibility — a consequence, not a rule. An integration key acts for
 * an account whose role passes those markers, so without this it would reach every route its
 * account can, administration included. Here a non-session credential passes only where it was
 * invited:
 *
 * <ul>
 *   <li>an agent key, on a route marked {@link RequiresAgentKey};
 *   <li>an integration key, on a route marked {@link AcceptsApiKey} with a scope the key holds —
 *       and within a request budget per key, so a leaked or looping key cannot flood the control
 *       plane.
 * </ul>
 *
 * <p>Sessions and the SCIM token are not affected: the markers and the SCIM path rule govern them.
 */
@Component
public class CredentialConfinement implements HandlerInterceptor {

    private static final int MAX_TRACKED_KEYS = 10_000;

    private final int requestsPerMinute;

    private final Map<UUID, Bucket> buckets = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<UUID, Bucket> eldest) {
            return size() > MAX_TRACKED_KEYS;
        }
    });

    public CredentialConfinement(@Value("${vectispire.security.api-key-requests-per-minute:600}") int requestsPerMinute) {
        this.requestsPerMinute = requestsPerMinute > 0 ? requestsPerMinute : 600;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof VectispirePrincipal principal)) {
            return true;
        }

        if (principal.agent().isPresent()) {
            if (!marked(method, RequiresAgentKey.class)) {
                throw new CredentialNotAcceptedException("This route does not accept an agent key.");
            }
            return true;
        }

        if (principal.integration().isPresent()) {
            ApiKeyAuthService.Integration key = principal.integration().get();
            AcceptsApiKey accepts = method.getMethodAnnotation(AcceptsApiKey.class);
            if (accepts == null) {
                accepts = method.getBeanType().getAnnotation(AcceptsApiKey.class);
            }
            if (accepts == null) {
                throw new CredentialNotAcceptedException("This route does not accept an API key.");
            }
            ApiKeyScope needed = accepts.value();
            if (!key.scopes().contains(needed)) {
                throw new CredentialNotAcceptedException("This API key lacks the " + needed.wireName() + " scope.");
            }
            ConsumptionProbe probe = buckets.computeIfAbsent(key.keyId(), ignored -> newBucket()).tryConsumeAndReturnRemaining(1);
            if (!probe.isConsumed()) {
                throw new ApiKeyRateLimitedException(Duration.ofNanos(probe.getNanosToWaitForRefill()));
            }
        }
        return true;
    }

    private Bucket newBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder().capacity(requestsPerMinute).refillGreedy(requestsPerMinute, Duration.ofMinutes(1)).build())
                .build();
    }

    private static boolean marked(HandlerMethod method, Class<? extends java.lang.annotation.Annotation> marker) {
        return method.hasMethodAnnotation(marker) || method.getBeanType().isAnnotationPresent(marker);
    }

    /** Forgets every budget; tests only. */
    public void reset() {
        buckets.clear();
    }
}
