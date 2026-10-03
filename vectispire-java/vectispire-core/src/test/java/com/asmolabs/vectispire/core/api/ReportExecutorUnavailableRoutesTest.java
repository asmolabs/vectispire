package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.reportplugins.ReportExecutor;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportWorker;
import com.asmolabs.vectispire.core.settings.SettingsService;
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
}
