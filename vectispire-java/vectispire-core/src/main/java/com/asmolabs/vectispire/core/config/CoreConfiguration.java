package com.asmolabs.vectispire.core.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.asmolabs.vectispire.common.domain.auth.Sessions;
import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.common.domain.scans.ScanQueue.Policy;
import com.asmolabs.vectispire.core.repositories.UserSessions;
import java.time.Clock;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

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
     * The JSON mapper, declared rather than auto-configured.
     *
     * <p><b>Spring Boot 4 auto-configures Jackson 3</b> ({@code tools.jackson.databind}), and
     * this codebase is annotated with Jackson 2 ({@code com.fasterxml.jackson}) — the version
     * the domain's export records, the notification payload and the agent contract are written
     * against. Asking the container for a {@code com.fasterxml} mapper therefore finds nothing,
     * and the failure arrives as "no qualifying bean" halfway down a dependency chain rather
     * than as "your Jackson is the other one".
     *
     * <p>Migrating the annotations is a separate change with its own risk — the wire format of
     * three export documents and one agent protocol depends on them — so the version in use is
     * stated here, once, where the next person will look.
     */
    @Bean
    ObjectMapper objectMapper() {
        return JsonMapper.builder()
                .addModule(new JavaTimeModule())
                // Instants as ISO-8601 text, never as an epoch number. The frontend parses dates
                // and an auditor reads them; a number satisfies neither, and the default is a
                // number.
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                // An unknown field is the ordinary case of a newer agent talking to an older
                // control plane. Failing on it would turn every rolling upgrade into an outage.
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                // Nulls are written, not omitted. The Angular client distinguishes "this target
                // has never been scanned" from "the field is missing", and so does an agent
                // reading a task with no deployment key — omitting them would make both of those
                // look like a payload the other side failed to build.
                .build();
    }

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
     * The sealing primitive, with the platform's secure random.
     *
     * <p>A bean rather than a field, so a test can hand it a deterministic source and assert
     * what came out — which is the only way to test a construction whose whole purpose is that
     * two runs never produce the same bytes.
     */
    @Bean
    SealedEnvelope sealedEnvelope() {
        return new SealedEnvelope();
    }

    @Bean
    Policy scanQueuePolicy(QueueProperties properties) {
        return new Policy(properties.lease(), properties.maxAttempts(), properties.claimAttempts());
    }

    @Bean
    Sessions.Policy sessionPolicy(SessionProperties properties) {
        return new Sessions.Policy(properties.absoluteLifetime(), properties.idleLifetime());
    }

    /**
     * @param absoluteLifetime past this, a session ends however active it has been. It is what
     *     bounds a stolen token's usefulness, and no amount of activity may extend it
     * @param idleLifetime past this without a request, a session ends. It is what protects an
     *     unlocked screen, and it is deliberately much shorter
     */
    @ConfigurationProperties("vectispire.session")
    public record SessionProperties(
            @DefaultValue("12h") Duration absoluteLifetime, @DefaultValue("60m") Duration idleLifetime) {}

    /**
     * @param claimAttempts how many times a claim retries before giving up on a round.
     *     <b>Exists for MySQL</b>, which counts skipped rows against its {@code LIMIT}: ten
     *     concurrent claimants against a queue of twenty left six empty-handed. Nothing was ever
     *     claimed twice — it was a throughput problem, whose production shape is an agent
     *     polling for thirty seconds while work waits
     */
    @ConfigurationProperties("vectispire.queue")
    public record QueueProperties(
            @DefaultValue("20m") Duration lease,
            @DefaultValue("3") int maxAttempts,
            @DefaultValue("12") int claimAttempts) {}

    /**
     * The periodic jobs' threads.
     *
     * <p><b>Declared rather than left to the default, because the default is one thread.</b>
     * Spring Boot's auto-configured scheduler has a pool size of 1, and four {@code @Scheduled}
     * jobs sat on it: the worker tick, the outbox relay, the scan scheduler and the hourly
     * maintenance. One slow job did not delay the others, it stopped them — a notification
     * waited on a purge, and the purge waited on whatever ran before it.
     *
     * <p>One thread per job, so a job's period means what it says whatever the others are doing.
     * A fifth job would still be safe: these are periodic and short, and they queue rather than
     * overlap.
     */
    @Bean
    ThreadPoolTaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(4);
        scheduler.setThreadNamePrefix("vectispire-jobs-");
        // Named on purpose: `@Scheduled` resolves a bean called `taskScheduler` when more than
        // one TaskScheduler exists, and the one below is the other one. Renaming this bean
        // silently moves every periodic job onto the agents' scheduler.
        scheduler.setAwaitTerminationSeconds(10);
        scheduler.setWaitForTasksToCompleteOnShutdown(true);
        return scheduler;
    }

    /**
     * The agents' long polls, on threads of their own.
     *
     * <p><b>This separation is the point, not the pool size.</b> {@code AgentJobPoller} parks a
     * {@code DeferredResult} and re-checks the queue on a scheduled task; it used to schedule
     * that on the same single thread as the jobs above. So a local scan running in the worker
     * tick — minutes, since a scan clones a repository and runs four containers — held the
     * thread that hands work to <em>remote</em> agents. The built-in worker did not slow the
     * fleet down, it stopped it, which is the opposite of what decision 0003 separates them for.
     *
     * <p>These tasks are short: look at the queue, complete the result or reschedule. Two
     * threads carry a fleet, and the waiting itself costs none — that is what the
     * {@code DeferredResult} is for.
     */
    @Bean
    ThreadPoolTaskScheduler agentPollScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(2);
        scheduler.setThreadNamePrefix("vectispire-agentpoll-");
        scheduler.setAwaitTerminationSeconds(10);
        scheduler.setWaitForTasksToCompleteOnShutdown(false);
        return scheduler;
    }
}
