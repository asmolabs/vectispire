package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.services.PlatformMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The instruments exist, and they are wired to the registry rather than to nothing.
 *
 * <p><b>Why this exists.</b> A meter that is never registered is invisible in exactly the way a
 * meter that reads zero is: the dashboard has no line, and six months later nobody can say
 * whether the number is zero or the instrument was never built. The only assertion that
 * distinguishes the two is asking the registry, which is what this does.
 *
 * <p>It does not assert the <em>values</em> — a gauge over an empty test database reads zero and
 * proves nothing. What it asserts is registration, naming and tagging, because those are what a
 * dashboard is written against and what a rename silently breaks.
 */
@DisplayName("the platform meters")
class PlatformMetricsTest extends ApiTestBase {

    @Autowired
    private MeterRegistry registry;

    @Autowired
    private PlatformMetrics metrics;

    @Test
    @DisplayName("are all registered under one prefix an operator can search for")
    void are_all_registered_under_one_prefix() {
        List<String> gauges = registry.getMeters().stream()
                .map(meter -> meter.getId().getName())
                .filter(name -> name.startsWith("vectispire."))
                .toList();

        assertThat(gauges)
                .contains(
                        "vectispire.scans.queued",
                        "vectispire.scans.running",
                        "vectispire.outbox.pending",
                        "vectispire.agents.enabled");
    }

    @Test
    @DisplayName("record a scan's duration under the tags a dashboard splits on")
    void record_a_scan_duration_with_its_tags() {
        metrics.scanFinishedSince(java.time.Instant.now().minus(Duration.ofSeconds(42)), true, false);
        metrics.scanFinishedSince(java.time.Instant.now().minus(Duration.ofSeconds(7)), false, true);

        assertThat(registry.find("vectispire.scans.duration")
                        .tag("outcome", "completed")
                        .tag("executor", "embedded")
                        .timer())
                .isNotNull()
                .satisfies(timer -> assertThat(timer.count()).isEqualTo(1));

        assertThat(registry.find("vectispire.scans.duration")
                        .tag("outcome", "failed")
                        .tag("executor", "agent")
                        .timer())
                .as("an agent that stops finishing scans must be visible apart from the embedded worker")
                .isNotNull();
    }

    @Test
    @DisplayName("record nothing at all for a scan whose claim is already gone")
    void record_nothing_when_the_claim_is_gone() {
        io.micrometer.core.instrument.search.Search before = registry.find("vectispire.scans.duration");
        long recorded = before.timers().stream().mapToLong(t -> t.count()).sum();

        metrics.scanFinishedSince(null, true, true);

        long after = registry.find("vectispire.scans.duration").timers().stream()
                .mapToLong(t -> t.count())
                .sum();
        assertThat(after)
                .as("an invented duration is worse than a missing one")
                .isEqualTo(recorded);
    }

    @Test
    @DisplayName("count a long poll answered with work apart from one answered empty")
    void count_polls_by_outcome() {
        metrics.agentPolled(true);
        metrics.agentPolled(false);
        metrics.agentPolled(false);

        assertThat(registry.find("vectispire.agents.polls").tag("outcome", "job").counter())
                .isNotNull()
                .satisfies(counter -> assertThat(counter.count()).isEqualTo(1.0));
        assertThat(registry.find("vectispire.agents.polls").tag("outcome", "idle").counter())
                .isNotNull()
                .satisfies(counter -> assertThat(counter.count()).isEqualTo(2.0));
    }

    @Test
    @DisplayName("are behind authentication, because a probe is not a metrics scrape")
    void are_behind_authentication() throws Exception {
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/actuator/metrics"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status()
                        .isUnauthorized());

        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/actuator/health"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status()
                        .isOk());
    }
}
