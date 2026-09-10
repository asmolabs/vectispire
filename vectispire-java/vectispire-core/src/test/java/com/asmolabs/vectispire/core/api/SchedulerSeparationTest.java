package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireContextTest;
import java.lang.reflect.Field;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

/**
 * The agents' long polls do not share a thread pool with the background jobs.
 *
 * <p><b>Why this exists.</b> Neither pool is declared by anything a reader would connect to the
 * other, and the failure they prevent is silent: with one shared scheduler — Spring Boot's
 * default, of size one — a background job holding the thread simply meant agents were handed no
 * work, for as long as it held it. Nothing logs that, and no other assertion looks at it.
 *
 * <p>Two ways this regresses, and both are covered below: someone deletes the qualifier on
 * {@code AgentJobPoller}, or someone renames the {@code taskScheduler} bean — after which
 * {@code @Scheduled} resolves the <em>agents'</em> scheduler and the two are one again, with no
 * compilation error and no test failure anywhere else.
 */
@DisplayName("the agents' scheduler")
class SchedulerSeparationTest extends VectispireContextTest {

    @Autowired
    private ApplicationContext context;

    @Autowired
    private AgentJobPoller poller;

    @Test
    @DisplayName("is a different pool from the one the periodic jobs run on")
    void is_a_different_pool_from_the_jobs() {
        TaskScheduler jobs = context.getBean("taskScheduler", TaskScheduler.class);
        TaskScheduler polls = context.getBean("agentPollScheduler", TaskScheduler.class);

        assertThat(polls).isNotSameAs(jobs);
    }

    @Test
    @DisplayName("is the one the poller actually holds")
    void is_the_one_the_poller_holds() throws Exception {
        // Reflection, because the wiring is the assertion: the poller exposes no accessor, and
        // adding one so a test can look would be widening an API for the test's convenience.
        Field field = AgentJobPoller.class.getDeclaredField("scheduler");
        field.setAccessible(true);
        Object held = field.get(poller);

        assertThat(held)
                .as("a missing @Qualifier would silently hand it the jobs' scheduler")
                .isSameAs(context.getBean("agentPollScheduler", TaskScheduler.class));
    }

    @Test
    @DisplayName("leaves the jobs enough threads to not queue behind each other")
    void leaves_the_jobs_enough_threads() {
        ThreadPoolTaskScheduler jobs = context.getBean("taskScheduler", ThreadPoolTaskScheduler.class);

        // Four @Scheduled methods: the worker tick, the outbox relay, the scan scheduler and the
        // hourly maintenance. One each — the default of 1 is what this replaces.
        assertThat(jobs.getPoolSize()).isGreaterThanOrEqualTo(4);
    }
}
