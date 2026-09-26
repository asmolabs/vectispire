package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.scanning.internal.PlatformMetrics;
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

    /** The two agent meters moved with the agent row into {@code agents} (decision 0029). */
    @Autowired
    private com.asmolabs.vectispire.core.agents.AgentMetrics agentMetrics;

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
        // Counted from where the registry stood, not from zero: the context — and its registry —
        // is shared with every HTTP test, and one that polls the real claim route has already
        // counted its own polls by the time this runs, in whatever order the suite chose.
        double jobsBefore = polls("job");
        double idleBefore = polls("idle");

        agentMetrics.agentPolled(true);
        agentMetrics.agentPolled(false);
        agentMetrics.agentPolled(false);

        assertThat(polls("job") - jobsBefore).isEqualTo(1.0);
        assertThat(polls("idle") - idleBefore).isEqualTo(2.0);
        assertThat(registry.find("vectispire.agents.polls").tag("outcome", "job").counter()).isNotNull();
        assertThat(registry.find("vectispire.agents.polls").tag("outcome", "idle").counter()).isNotNull();
    }

    private double polls(String outcome) {
        io.micrometer.core.instrument.Counter counter =
                registry.find("vectispire.agents.polls").tag("outcome", outcome).counter();
        return counter == null ? 0.0 : counter.count();
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

    @Test
    @DisplayName("are an administrator's session's to read, and no other credential's")
    void areAnAdministratorsSessionsOnly() throws Exception {
        // The MVC confinement — an agent key to the agent protocol, an integration key to the
        // routes of its scope, a session owing a password change to that change — does not reach
        // Actuator, whose endpoints are not the application's handlers. Each of these read the
        // instance's internal structure and volumes.
        String agentKey = json.readTree(mvc.perform(authenticated(
                                org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/admin/agents"),
                                asAdmin())
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"metrics-probe-" + System.nanoTime() + "\"}"))
                .andReturn().getResponse().getContentAsString()).get("secret").asText();
        String integrationKey = json.readTree(mvc.perform(authenticated(
                                org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/api-keys"),
                                asAdmin())
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"metrics-probe\", \"scopes\": [\"read\"]}"))
                .andReturn().getResponse().getContentAsString()).get("secret").asText();

        for (String endpoint : List.of("/actuator/metrics", "/actuator/info")) {
            for (String refused : List.of(agentKey, integrationKey, asReader(), asCiso(), asPendingPasswordChange())) {
                mvc.perform(authenticated(
                                org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(endpoint), refused))
                        .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status()
                                .isForbidden());
            }
            mvc.perform(authenticated(
                            org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get(endpoint), asAdmin()))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());
        }
        // The probe stays open: a container's health check has no session.
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/actuator/health/liveness"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());
    }
}
