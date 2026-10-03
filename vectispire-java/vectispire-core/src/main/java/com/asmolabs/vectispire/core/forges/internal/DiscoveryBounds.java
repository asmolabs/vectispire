package com.asmolabs.vectispire.core.forges.internal;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * A discovery's bounds (decision 0037 §3, answer 8): thirty minutes and twenty thousand repositories per run, a
 * rate-limit wait of up to a minute spent inside it. Past either bound the run ends partial; a longer wait ends it
 * partial too, saying when the limit lifts. Configurable so that a test reaches each bound in seconds, not because
 * an installation should move them: a larger estate is discovered per group.
 */
@Component
public class DiscoveryBounds {

    private final Duration maxDuration;
    private final int maxRepositories;
    private final Duration maxRateLimitWait;

    public DiscoveryBounds(
            @Value("${vectispire.forges.discovery.max-duration:30m}") Duration maxDuration,
            @Value("${vectispire.forges.discovery.max-repositories:20000}") int maxRepositories,
            @Value("${vectispire.forges.discovery.max-rate-limit-wait:60s}") Duration maxRateLimitWait) {
        this.maxDuration = maxDuration;
        this.maxRepositories = Math.max(1, maxRepositories);
        this.maxRateLimitWait = maxRateLimitWait;
    }

    public Duration maxDuration() {
        return maxDuration;
    }

    public int maxRepositories() {
        return maxRepositories;
    }

    public Duration maxRateLimitWait() {
        return maxRateLimitWait;
    }
}
