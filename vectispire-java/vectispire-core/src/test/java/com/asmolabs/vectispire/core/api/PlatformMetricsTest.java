package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.agents.AgentMetrics;
import com.asmolabs.vectispire.core.scanning.internal.PlatformMetrics;
import com.asmolabs.vectispire.core.scanning.internal.ScanMetricsTask;
import com.asmolabs.vectispire.core.agents.internal.AgentMetricsTask;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The instruments exist, they are wired to the registry rather than to nothing, and the gauges read
 * what the tick found rather than the database.
 *
 * <p><b>Why this exists.</b> A meter that is never registered is invisible in exactly the way a
 * meter that reads zero is: the dashboard has no line, and six months later nobody can say
 * whether the number is zero or the instrument was never built. The only assertion that
 * distinguishes the two is asking the registry, which is what this does.
 *
 * <p>The figures are asserted through the tasks the tick runs — the beans the application
 * contributes, not a call on the meters' class — since the tick is the gauges' only reader of the
 * database ({@code MaintenanceCompositionTest} holds the tick to those tasks).
 */
@DisplayName("the platform meters")
class PlatformMetricsTest extends ApiTestBase {

    @Autowired
    private MeterRegistry registry;

    @Autowired
    private PlatformMetrics metrics;

    /** The agent meters moved with the agent row into {@code agents} (decision 0029). */
    @Autowired
    private AgentMetrics agentMetrics;

    @Autowired
    private ScanMetricsTask scanTick;

    @Autowired
    private AgentMetricsTask agentTick;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Test
    @DisplayName("are all registered under one prefix an operator can search for")
    void are_all_registered_under_one_prefix() {
        List<String> names = registry.getMeters().stream()
                .map(meter -> meter.getId().getName())
                .filter(name -> name.startsWith("vectispire."))
                .toList();

        assertThat(names)
                .contains(
                        "vectispire.scans.queued",
                        "vectispire.scans.queued.oldest.age",
                        "vectispire.scans.running",
                        "vectispire.scans.started",
                        "vectispire.scans.completed",
                        "vectispire.scans.failed",
                        "vectispire.scans.lapsed",
                        "vectispire.outbox.pending",
                        "vectispire.agents.enabled",
                        "vectispire.agents.online",
                        "vectispire.agents.last.seen.age",
                        "vectispire.agents.polls",
                        "vectispire.agents.claims",
                        "vectispire.scans.credential.unserved",
                        "vectispire.metrics.snapshot.age");
    }

    @Test
    @DisplayName("count the waiting scans by kind at the tick, and a scrape does not query")
    void the_queue_gauges_read_the_tick() {
        waiting(repositoryScan(), Duration.ofMinutes(10));
        waiting(repositoryScan(), Duration.ofMinutes(1));
        waiting(containerScan(), Duration.ofSeconds(30));

        scanTick.run();

        assertThat(gauge("vectispire.scans.queued", "repository")).isEqualTo(2.0);
        assertThat(gauge("vectispire.scans.queued", "container")).isEqualTo(1.0);
        assertThat(gauge("vectispire.scans.queued.oldest.age", "repository"))
                .as("the oldest repository scan waited ten minutes")
                .isGreaterThanOrEqualTo(600.0)
                .isLessThan(660.0);
        assertThat(registry.get("vectispire.metrics.snapshot.age").tag("source", "scans").gauge().value())
                .isCloseTo(0.0, within(30.0));

        // **The gauge's figure is the tick's**: a scan queued since is not seen until the next one.
        // A gauge that counted at the scrape would read three here, and a scrape would be a query on
        // a pool the incident may have exhausted.
        waiting(repositoryScan(), Duration.ZERO);
        assertThat(gauge("vectispire.scans.queued", "repository")).isEqualTo(2.0);

        scanTick.run();
        assertThat(gauge("vectispire.scans.queued", "repository")).isEqualTo(3.0);
    }

    @Test
    @DisplayName("count an attempt's start and end under the tags a dashboard splits on, and time it")
    void count_and_time_an_attempt() {
        ScanEntity repository = claimed(Duration.ofSeconds(42));
        repository.setRepoId(1L);
        ScanEntity container = claimed(Duration.ofSeconds(7));
        container.setContainerId(1L);

        double startedBefore = count("vectispire.scans.started", "repository", "embedded");
        double completedBefore = count("vectispire.scans.completed", "repository", "embedded");
        double finalBefore = failures("container", "agent", true);
        double retriedBefore = failures("container", "agent", false);

        metrics.scanStarted(repository, PlatformMetrics.Executor.EMBEDDED);
        metrics.scanCompleted(repository, PlatformMetrics.Executor.EMBEDDED);
        metrics.scanFailed(container, PlatformMetrics.Executor.AGENT, true);

        assertThat(count("vectispire.scans.started", "repository", "embedded") - startedBefore).isEqualTo(1.0);
        assertThat(count("vectispire.scans.completed", "repository", "embedded") - completedBefore).isEqualTo(1.0);
        assertThat(failures("container", "agent", true) - finalBefore)
                .as("a scan failed for good apart from an attempt that will be retried")
                .isEqualTo(1.0);
        assertThat(failures("container", "agent", false) - retriedBefore).isZero();

        assertThat(registry.find("vectispire.scans.duration")
                        .tag("outcome", "completed")
                        .tag("executor", "embedded")
                        .tag("kind", "repository")
                        .timer())
                .isNotNull()
                .satisfies(timer -> assertThat(timer.max(java.util.concurrent.TimeUnit.SECONDS)).isGreaterThanOrEqualTo(42.0));
        assertThat(registry.find("vectispire.scans.duration")
                        .tag("outcome", "failed")
                        .tag("executor", "agent")
                        .tag("kind", "container")
                        .timer())
                .as("an agent that stops finishing scans must be visible apart from the embedded worker")
                .isNotNull();
    }

    @Test
    @DisplayName("record nothing at all for a scan whose claim is already gone")
    void record_nothing_when_the_claim_is_gone() {
        long recorded = registry.find("vectispire.scans.duration").timers().stream()
                .mapToLong(t -> t.count())
                .sum();
        double completed = registry.find("vectispire.scans.completed").counters().stream()
                .mapToDouble(Counter::count)
                .sum();

        metrics.scanCompleted(null, PlatformMetrics.Executor.AGENT);
        metrics.scanFailed(null, PlatformMetrics.Executor.AGENT, false);

        assertThat(registry.find("vectispire.scans.duration").timers().stream()
                        .mapToLong(t -> t.count())
                        .sum())
                .as("an invented duration is worse than a missing one")
                .isEqualTo(recorded);
        assertThat(registry.find("vectispire.scans.completed").counters().stream()
                        .mapToDouble(Counter::count)
                        .sum())
                .isEqualTo(completed);
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
    }

    @Test
    @DisplayName("count the agents enabled and online at the tick, and a claim through the real poll")
    void the_agent_gauges_and_a_claim() throws Exception {
        String agentKey = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"metrics-agent-" + System.nanoTime() + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).get("secret").asText();

        agentTick.run();
        assertThat(registry.get("vectispire.agents.enabled").gauge().value()).isEqualTo(1.0);
        assertThat(registry.get("vectispire.agents.online").gauge().value())
                .as("declared, never heard from")
                .isZero();

        // A container image scan: no credential to seal, so any agent may be handed it.
        waiting(containerScan(), Duration.ZERO);
        double delivered = claims("delivered");
        double started = count("vectispire.scans.started", "container", "agent");

        MvcResult poll = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agentKey))
                .andReturn();
        mvc.perform(asyncDispatch(poll)).andExpect(status().isOk());

        assertThat(claims("delivered") - delivered).isEqualTo(1.0);
        assertThat(count("vectispire.scans.started", "container", "agent") - started).isEqualTo(1.0);

        agentTick.run();
        assertThat(registry.get("vectispire.agents.online").gauge().value())
                .as("the poll is a word from the agent")
                .isEqualTo(1.0);
        assertThat(registry.get("vectispire.agents.last.seen.age").gauge().value()).isLessThan(30.0);
    }

    private double gauge(String name, String kind) {
        return registry.get(name).tag("kind", kind).gauge().value();
    }

    private double count(String name, String kind, String executor) {
        return registry.get(name).tag("kind", kind).tag("executor", executor).counter().count();
    }

    private double failures(String kind, String executor, boolean finalFailure) {
        return registry.get("vectispire.scans.failed")
                .tag("kind", kind)
                .tag("executor", executor)
                .tag("final", String.valueOf(finalFailure))
                .counter()
                .count();
    }

    private double polls(String outcome) {
        return registry.get("vectispire.agents.polls").tag("outcome", outcome).counter().count();
    }

    private double claims(String outcome) {
        return registry.get("vectispire.agents.claims").tag("outcome", outcome).counter().count();
    }

    private static ScanEntity claimed(Duration ago) {
        ScanEntity scan = new ScanEntity();
        scan.setClaimedAt(Instant.now().minus(ago));
        return scan;
    }

    private void waiting(ScanEntity scan, Duration queuedAgo) {
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(Instant.now().minus(queuedAgo));
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(0);
        scans.save(scan);
    }

    private ScanEntity repositoryScan() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/metrics-" + System.nanoTime() + ".git");
        repository.setName("metrics");
        repository.setBranch("main");
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositories.save(repository).getId());
        scan.setBranch("main");
        return scan;
    }

    private ScanEntity containerScan() {
        ContainerEntity image = new ContainerEntity();
        image.setImageName("team/metrics-" + System.nanoTime());
        image.setTag("1.0");
        ScanEntity scan = new ScanEntity();
        scan.setContainerId(containers.save(image).getId());
        scan.setBranch("");
        return scan;
    }
}
