package com.asmolabs.vectispire.core.access.web.security;

import java.time.Duration;

/** An integration key past its request budget; answered 429 with {@code Retry-After}. */
public class ApiKeyRateLimitedException extends RuntimeException {

    private final Duration retryAfter;

    public ApiKeyRateLimitedException(Duration retryAfter) {
        super("This API key has made too many requests. Try again in " + Math.max(1, retryAfter.toSeconds()) + " seconds.");
        this.retryAfter = retryAfter;
    }

    public Duration retryAfter() {
        return retryAfter;
    }
}
