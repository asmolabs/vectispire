package com.asmolabs.vectispire.core.access.web.security;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * The request chain's ceilings and the proxies it believes, {@code vectispire.security.*}.
 *
 * <p><b>No defaults here, on purpose.</b> Each ceiling's shipped value, and why it is that value,
 * lives on the class that applies it, which also replaces a zero or a negative with it rather than
 * lock the deployment out of itself; a default here as well would be the second copy each injected
 * value used to carry beside that constant. An unset number binds as {@code 0} and an unset window as
 * {@code null}, which every reader already reads as "the shipped value".
 *
 * @param trustedProxies whose {@code X-Forwarded-For} to believe, comma-separated; empty trusts nobody
 *     ({@link TrustedProxies})
 * @param loginAttemptsPerWindow sign-in attempts per address ({@code LoginRateLimitFilter})
 * @param loginAttemptWindow the window they refill over
 * @param bearerFailuresPerWindow refused bearer tokens per address ({@code BearerRateLimitFilter})
 * @param bearerFailureWindow the window they refill over
 * @param webhookRequestsPerWindow tracker deliveries per address ({@code WebhookRateLimitFilter})
 * @param webhookRequestWindow the window they refill over
 * @param apiKeyRequestsPerMinute requests per API key ({@code CredentialConfinement})
 */
@Validated
@ConfigurationProperties("vectispire.security")
public record SecurityLimits(
        String trustedProxies,
        int loginAttemptsPerWindow,
        Duration loginAttemptWindow,
        int bearerFailuresPerWindow,
        Duration bearerFailureWindow,
        int webhookRequestsPerWindow,
        Duration webhookRequestWindow,
        int apiKeyRequestsPerMinute) {

    public SecurityLimits {
        trustedProxies = trustedProxies == null ? "" : trustedProxies;
    }
}
