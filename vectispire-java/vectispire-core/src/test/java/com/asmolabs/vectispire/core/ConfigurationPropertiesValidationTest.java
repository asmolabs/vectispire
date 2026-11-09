package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.config.CoreConfiguration;
import com.asmolabs.vectispire.core.scanning.WorkerProperties;
import com.asmolabs.vectispire.core.scanning.internal.LeaderProperties;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.validation.BindValidationException;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

/**
 * The configuration bounds that are surely a mistake stop the start, saying which property and why.
 *
 * <p><b>Bound by Spring, as the application binds them</b>: a constructor called by hand would prove the
 * record and nothing about whether the binder validates it — which, without {@code @Validated} on the
 * type, it does not, and a constraint then binds a zero as happily as a two.
 */
@DisplayName("configuration bounds")
class ConfigurationPropertiesValidationTest {

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties({
        WorkerProperties.class,
        LeaderProperties.class,
        CoreConfiguration.SessionProperties.class,
        CoreConfiguration.QueueProperties.class
    })
    static class Bound {}

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(Bound.class);

    @Test
    @DisplayName("nothing set: the defaults are what they were")
    void defaultsUnchanged() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            WorkerProperties worker = context.getBean(WorkerProperties.class);
            assertThat(worker.enabled()).isTrue();
            assertThat(worker.maxConcurrent()).isEqualTo(2);
            assertThat(context.getBean(LeaderProperties.class).lease()).isEqualTo(Duration.ofSeconds(180));
            CoreConfiguration.SessionProperties session = context.getBean(CoreConfiguration.SessionProperties.class);
            assertThat(session.absoluteLifetime()).isEqualTo(Duration.ofHours(12));
            assertThat(session.idleLifetime()).isEqualTo(Duration.ofMinutes(60));
            CoreConfiguration.QueueProperties queue = context.getBean(CoreConfiguration.QueueProperties.class);
            assertThat(queue.lease()).isEqualTo(Duration.ofMinutes(20));
            assertThat(queue.maxAttempts()).isEqualTo(3);
            assertThat(queue.claimAttempts()).isEqualTo(12);
        });
    }

    @Test
    @DisplayName("a worker running no scans at once is refused, no longer read as two")
    void workerConcurrency() {
        runner.withPropertyValues("vectispire.worker.max-concurrent=0")
                .run(context -> assertRefused(context, "vectispire.worker", "maxConcurrent", "VECTISPIRE_EMBEDDED_WORKER=false"));
        runner.withPropertyValues("vectispire.worker.max-concurrent=4")
                .run(context -> assertThat(context.getBean(WorkerProperties.class).maxConcurrent()).isEqualTo(4));
    }

    @Test
    @DisplayName("a duration with its unit forgotten — milliseconds — is refused")
    void durationsOfASecondAtLeast() {
        runner.withPropertyValues("vectispire.session.idle-lifetime=60")
                .run(context -> assertRefused(context, "vectispire.session", "idleLifetime", "a bare number is read as milliseconds"));
        runner.withPropertyValues("vectispire.session.absolute-lifetime=0s")
                .run(context -> assertRefused(context, "vectispire.session", "absoluteLifetime", "at least one second"));
        runner.withPropertyValues("vectispire.leader.lease=180")
                .run(context -> assertRefused(context, "vectispire.leader", "lease", "at least one second"));
        runner.withPropertyValues("vectispire.queue.lease=0s")
                .run(context -> assertRefused(context, "vectispire.queue", "lease", "at least one second"));
        runner.withPropertyValues("vectispire.leader.lease=1s")
                .run(context -> assertThat(context.getBean(LeaderProperties.class).lease()).isEqualTo(Duration.ofSeconds(1)));
    }

    @Test
    @DisplayName("a queue that would never try or never claim is refused")
    void queueAttempts() {
        runner.withPropertyValues("vectispire.queue.max-attempts=0")
                .run(context -> assertRefused(context, "vectispire.queue", "maxAttempts", "no scan ever runs"));
        runner.withPropertyValues("vectispire.queue.claim-attempts=-1")
                .run(context -> assertRefused(context, "vectispire.queue", "claimAttempts", "no scan is ever claimed"));
    }

    private static void assertRefused(AssertableApplicationContext context, String prefix, String field, String reason) {
        assertThat(context).hasFailed();
        assertThat(context.getStartupFailure())
                .rootCause()
                .isInstanceOf(BindValidationException.class)
                .hasMessageContaining(prefix)
                .hasMessageContaining(field)
                .hasMessageContaining(reason);
    }
}
