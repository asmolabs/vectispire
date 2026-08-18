package com.asmolabs.zanshin.core.config;

import com.asmolabs.zanshin.common.domain.net.OutboundUrlGuard;
import com.asmolabs.zanshin.common.domain.scans.ScanQueue.Policy;
import java.time.Clock;
import java.time.Duration;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The beans the domain's pure rules need in order to be applied.
 *
 * <p>Every value the domain takes as a parameter is bound here rather than read where it is
 * used. That is the reason those types take parameters at all: a lease duration read from the
 * environment inside the rule cannot be varied by a test, and a lease duration nobody can vary
 * in a test is one nobody has ever seen expire.
 */
@Configuration
public class CoreConfiguration {

    /**
     * The clock, injected everywhere rather than called.
     *
     * <p>{@code Instant.now()} scattered through services is the thing that makes a scheduling
     * rule untestable — and scheduling rules are exactly the ones whose errors take a day to
     * show up.
     */
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * The guard every outbound URL passes, with the default resolver.
     *
     * <p>A bean rather than a {@code new} at each call site, so a deployment that needs a
     * different resolver — a test, a machine with no DNS — replaces one thing and not seven.
     */
    @Bean
    OutboundUrlGuard outboundUrlGuard() {
        return new OutboundUrlGuard();
    }

    @Bean
    Policy scanQueuePolicy(QueueProperties properties) {
        return new Policy(properties.lease(), properties.maxAttempts(), properties.claimAttempts());
    }

    /**
     * @param claimAttempts how many times a claim retries before giving up on a round.
     *     <b>Exists for MySQL</b>, which counts skipped rows against its {@code LIMIT}: ten
     *     concurrent claimants against a queue of twenty left six empty-handed. Nothing was ever
     *     claimed twice — it was a throughput problem, whose production shape is an agent
     *     polling for thirty seconds while work waits
     */
    @ConfigurationProperties("zanshin.queue")
    public record QueueProperties(
            @DefaultValue("20m") Duration lease,
            @DefaultValue("3") int maxAttempts,
            @DefaultValue("12") int claimAttempts) {}
}
