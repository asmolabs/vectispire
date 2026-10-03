package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.common.scanning.scanners.ReportPluginRenderer;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.reportplugins.ReportExecutor;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportQueue;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportRunSweepTask;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportWorker;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.ResultActions;

/**
 * A report run's lease, in real time (decision 0035 §2, lot R3): renewed while its executor carries it out, so a
 * run longer than the lease is not failed as lost; still lapsing once nobody renews it; and a run nobody claims for
 * a whole lease, while no executor works, failed rather than left waiting for ever.
 *
 * <p><b>A lease of three seconds</b>, so that a run can outlive it within a test: the renewal is a heartbeat on a
 * clock of its own, which no stand-in for the database's clock would move. The stand-in for the container is
 * {@link ReportRunsRoutesTest}'s, and the turn is {@link ReportWorker#drain}, the worker's own on the test's thread.
 */
@TestPropertySource(properties = "vectispire.reports.lease=PT3S")
@DisplayName("report runs, their lease in real time")
class ReportRunLeaseRoutesTest extends ApiTestBase {

    private static final Duration LEASE = Duration.ofSeconds(3);
    private static final byte[] DOCUMENT = "summary, rendered".getBytes(StandardCharsets.UTF_8);

    @MockitoBean
    private ReportExecutor executor;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private ReportWorker worker;

    @Autowired
    private ReportQueue queue;

    @Autowired
    private ReportRunSweepTask sweep;

    @Autowired
    private JdbcTemplate jdbc;

    private long project;
    private long otherProject;

    @BeforeEach
    void estate() throws Exception {
        reset(executor);
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        String governor = tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Payments " + System.nanoTime()))))
                .andExpect(status().isCreated()));
        project = project(solution, "Checkout");
        otherProject = project(solution, "Ledger");
        mvc.perform(authenticated(post("/api/v1/report-plugins"), governor)
                .contentType(MediaType.APPLICATION_JSON).content(write(ReportPluginsRoutesTest.manifest(
                        ReportRunsRoutesTest.IMAGE)))).andExpect(status().isCreated());
        for (long each : List.of(project, otherProject)) {
            mvc.perform(authenticated(put("/api/v1/projects/" + each + "/report-plugins/summary"), asCiso()))
                    .andExpect(status().isOk());
        }
    }

    private long project(long solution, String name) throws Exception {
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", name))))
                .andExpect(status().isCreated()));
    }

    private ResultActions request(long projectId) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/projects/" + projectId + "/reports"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("pluginId", "summary"))));
    }

    private JsonNode body(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }

    private long idOf(ResultActions result) throws Exception {
        return body(result).path("id").asLong();
    }

    private JsonNode run(long projectId, long runId) throws Exception {
        return body(mvc.perform(authenticated(get("/api/v1/projects/" + projectId + "/reports/" + runId), asAdmin()))
                .andExpect(status().isOk()));
    }

    private List<AuditLogEntity> entries(AuditOperation operation) {
        return auditLog.findAll().stream().filter(entry -> operation.wireName().equals(entry.getOperationType())).toList();
    }

    @Test
    @DisplayName("a run carried out past its lease is renewed by its executor, and produces; a lost one beside it lapses")
    void renewedWhileAlive() throws Exception {
        // A sibling took a run and died with it: nobody renews that one.
        long abandoned = idOf(request(otherProject).andExpect(status().isAccepted()));
        assertThat(queue.claim("dead-instance")).contains(abandoned);
        long runId = idOf(request(project).andExpect(status().isAccepted()));

        // What another instance's turn would find, asked while the run has lasted twice its lease.
        AtomicReference<List<Long>> lapsedMeanwhile = new AtomicReference<>();
        when(executor.render(any(), any())).thenAnswer(call -> {
            Thread.sleep(LEASE.multipliedBy(2).plusMillis(500).toMillis());
            lapsedMeanwhile.set(queue.failLapsed());
            return new ReportPluginRenderer.Outcome.Produced(DOCUMENT);
        });
        assertThat(worker.drain()).isOne();

        assertThat(lapsedMeanwhile.get()).as("only the run nobody renewed lapsed").containsExactly(abandoned);
        assertThat(run(project, runId).at("/state").asText()).isEqualTo("produced");
        assertThat(entries(AuditOperation.REPORT_PRODUCED)).hasSize(1);
        JsonNode lost = run(otherProject, abandoned);
        assertThat(lost.at("/state").asText()).isEqualTo("failed");
        assertThat(lost.at("/reason").asText()).isEqualTo("executor_lost");
    }

    @Test
    @DisplayName("a renewal names its claimant: another executor's renewal extends nothing, and a lapsed run stays lost")
    void renewalNamesItsClaimant() throws Exception {
        long runId = idOf(request(project).andExpect(status().isAccepted()));
        assertThat(queue.claim("dead-instance")).contains(runId);
        assertThat(queue.renew(runId, "dead-instance")).isTrue();
        assertThat(queue.renew(runId, worker.identity())).as("not its run").isFalse();

        Thread.sleep(LEASE.plusMillis(500).toMillis());
        worker.drain();
        assertThat(run(project, runId).at("/reason").asText()).isEqualTo("executor_lost");
        assertThat(queue.renew(runId, "dead-instance")).as("too late: the run was failed as lost").isFalse();
        assertThat(entries(AuditOperation.REPORT_FAILED)).singleElement()
                .satisfies(entry -> assertThat(entry.getDescription()).contains("executor_lost"));
    }

    @Test
    @DisplayName("a run nobody claimed for a whole lease, while no executor ran anything, fails executor_unavailable")
    void unclaimed() throws Exception {
        long runId = idOf(request(project).andExpect(status().isAccepted()));
        sweep.run();
        assertThat(run(project, runId).at("/state").asText()).as("within its lease it waits").isEqualTo("pending");

        Thread.sleep(LEASE.plusMillis(500).toMillis());
        sweep.run();
        JsonNode failed = run(project, runId);
        assertThat(failed.at("/state").asText()).isEqualTo("failed");
        assertThat(failed.at("/reason").asText()).isEqualTo("executor_unavailable");
        assertThat(failed.at("/detail").asText()).contains("No executor claimed this run");
        assertThat(entries(AuditOperation.REPORT_FAILED)).singleElement()
                .satisfies(entry -> assertThat(entry.getDescription()).contains("executor_unavailable"));
        request(project).andExpect(status().isAccepted());
    }

    @Test
    @DisplayName("but not while an executor holds a run, nor when one started a run within the lease")
    void notWhileAnExecutorWorks() throws Exception {
        long busy = idOf(request(otherProject).andExpect(status().isAccepted()));
        assertThat(queue.claim("busy-instance")).contains(busy);
        long waiting = idOf(request(project).andExpect(status().isAccepted()));
        // A day back: the driver may read the timestamp in the JVM's zone, and an hour's offset must not leave it
        // inside the lease.
        jdbc.update("update t_report_run set requested_at = ? where id = ?",
                Timestamp.from(Instant.now().minusSeconds(86_400)), waiting);

        // Busy: the other run is in hand and its lease alive — the queue is long, not abandoned.
        sweep.run();
        assertThat(run(project, waiting).at("/state").asText()).isEqualTo("pending");

        // It ended a moment ago: an executor is there, between two claims.
        jdbc.update("update t_report_run set state = 'produced', active_key = null, claimed_by = null, "
                + "lease_expires_at = null, started_at = ? where id = ?", Timestamp.from(Instant.now()), busy);
        sweep.run();
        assertThat(run(project, waiting).at("/state").asText()).isEqualTo("pending");

        // Nothing started within the lease: nobody is there.
        jdbc.update("update t_report_run set started_at = ? where id = ?",
                Timestamp.from(Instant.now().minusSeconds(86_400)), busy);
        sweep.run();
        assertThat(run(project, waiting).at("/reason").asText()).isEqualTo("executor_unavailable");
    }
}
