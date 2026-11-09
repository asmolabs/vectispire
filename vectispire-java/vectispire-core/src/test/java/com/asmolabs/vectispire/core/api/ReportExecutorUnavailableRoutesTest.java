package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.reportplugins.ReportExecutor;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportRunSweepTask;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportWorker;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * An installation whose built-in worker is switched off — every scan on agents — has no container endpoint on the
 * control plane, and so no report plugins in this version (decision 0035 §2): a request is refused, 409 {@code
 * report-executor-unavailable}, and nothing is queued for nobody to claim. The API suite's own configuration is
 * that installation: {@code vectispire.worker.enabled} is false there.
 */
@DisplayName("report runs, on a control plane with no container endpoint")
class ReportExecutorUnavailableRoutesTest extends ApiTestBase {

    @Autowired
    private SettingsService settings;

    @Autowired
    private ApplicationContext context;

    @Autowired
    private ReportWorker worker;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ReportRunSweepTask sweep;

    @Autowired
    private AuditLogRepository auditLog;

    @Test
    @DisplayName("409 report-executor-unavailable, after the project and the role, and nothing queued")
    void refused() throws Exception {
        assertThat(context.getBeanNamesForType(ReportExecutor.class)).as("no executor where the worker is off").isEmpty();
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        String governor = tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
        long solution = json.readTree(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Payments " + System.nanoTime()))))
                .andReturn().getResponse().getContentAsString()).path("id").asLong();
        long project = json.readTree(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Checkout"))))
                .andReturn().getResponse().getContentAsString()).path("id").asLong();
        mvc.perform(authenticated(post("/api/v1/report-plugins"), governor)
                .contentType(MediaType.APPLICATION_JSON).content(write(ReportPluginsRoutesTest.manifest(
                        ReportRunsRoutesTest.IMAGE)))).andExpect(status().isCreated());
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/report-plugins/summary"), asCiso()))
                .andExpect(status().isOk());

        mvc.perform(authenticated(post("/api/v1/projects/" + (project + 100_000) + "/reports"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("pluginId", "summary"))))
                .andExpect(status().isNotFound());
        mvc.perform(authenticated(post("/api/v1/projects/" + project + "/reports"), governor)
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("pluginId", "summary"))))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(post("/api/v1/projects/" + project + "/reports"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("pluginId", "summary"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:vectispire:problem:report-executor-unavailable"));

        assertThat(jdbc.queryForObject("select count(*) from t_report_run", Long.class)).isZero();
        assertThat(worker.drain()).as("and the turn claims nothing it could not run").isZero();
    }

    @Test
    @DisplayName("restarted with the worker off, the runs queued and claimed before are failed, not kept for ever")
    void sweptWithoutAnExecutor() {
        // What an instance with an executor left before the restart: a run waiting, and one in hand whose
        // executor is gone. A day back, beyond any lease, whatever zone the driver reads a timestamp in.
        Timestamp dayAgo = Timestamp.from(Instant.now().minusSeconds(86_400));
        jdbc.update("insert into t_report_run (project_id, plugin_id, state, active_key, requested_at, requested_by, "
                + "requested_by_id) values (1, 'summary', 'pending', 'summary@1', ?, 'ada', 1)", dayAgo);
        jdbc.update("insert into t_report_run (project_id, plugin_id, state, active_key, requested_at, requested_by, "
                + "requested_by_id, claimed_by, started_at, lease_expires_at) values (2, 'summary', 'running', "
                + "'summary@2', ?, 'ada', 1, 'gone-instance', ?, ?)", dayAgo, dayAgo, dayAgo);
        assertThat(worker.drain()).as("the worker's turn is idle here").isZero();
        assertThat(jdbc.queryForList("select state from t_report_run", String.class)).containsOnly("pending", "running");

        sweep.run();

        assertThat(jdbc.queryForList("select reason from t_report_run where project_id = 1", String.class))
                .containsExactly("executor_unavailable");
        assertThat(jdbc.queryForList("select reason from t_report_run where project_id = 2", String.class))
                .containsExactly("executor_lost");
        assertThat(jdbc.queryForObject("select count(*) from t_report_run where active_key is not null", Long.class))
                .as("each plugin's turn for its project is free again").isZero();
        assertThat(auditLog.findAll()).filteredOn(entry -> AuditOperation.REPORT_FAILED.wireName()
                .equals(entry.getOperationType())).hasSize(2);
    }
}
