package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.asmolabs.zanshin.common.scanning.ScanRunner;
import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The built-in worker can actually scan.
 *
 * <p><b>This exists because it could not.</b> {@code ScanDispatcher} takes an {@code
 * Optional<ScanRunner>} and quietly claims nothing when it is empty; no bean ever supplied one,
 * so every queued scan stayed {@code pending} for ever. Nothing failed and nothing was logged —
 * the worker reports only rounds in which it claimed something — so the queue simply never
 * moved, on an install whose own defaults say the built-in worker is on.
 *
 * <p>Asserting a bean exists is a poor test of "scanning works" and is not trying to be one:
 * a real scan needs Docker and belongs to the integration campaign. This tests the single thing
 * that was wrong and that no other test could see — the wiring, and the condition that governs
 * it. The second case matters as much as the first: if the bean appeared unconditionally, the
 * dispatcher's empty branch would become unreachable and a control plane with no Docker socket
 * would claim work it cannot serve.
 */
@DisplayName("the built-in worker's runner")
class ScanningConfigurationTest {

    private final ApplicationContextRunner contexts = new ApplicationContextRunner()
            .withUserConfiguration(Dependencies.class, ScanningConfiguration.class);

    @Test
    @DisplayName("is wired by default, or the queue never moves and nothing says so")
    void theRunnerIsWiredByDefault() {
        contexts.run(context -> assertThat(context)
                .describedAs("without a ScanRunner bean the dispatcher claims nothing, silently")
                .hasSingleBean(ScanRunner.class));
    }

    @Test
    @DisplayName("is absent when the worker is switched off, so the guard stays meaningful")
    void noRunnerWhenTheWorkerIsOff() {
        contexts.withPropertyValues("zanshin.worker.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(ScanRunner.class));
    }

    @Configuration
    static class Dependencies {

        @Bean
        RuleSetService ruleSetService() {
            return mock(RuleSetService.class);
        }

        @Bean
        Clock clock() {
            return Clock.systemUTC();
        }
    }
}
