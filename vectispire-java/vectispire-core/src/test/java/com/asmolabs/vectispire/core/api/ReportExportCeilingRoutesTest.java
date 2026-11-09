package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportBounds;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunReason;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.common.scanning.scanners.ReportPluginRenderer;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.reportplugins.ReportExecutor;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportExportCeiling;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportWorker;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.ResultActions;

/**
 * A report run's export is built under the bound the database can keep (decision 0035 §1, {@link
 * ReportExportCeiling}): over it the run fails {@code export_too_large} <b>before the plugin runs</b>, saying why
 * the bound is lower and what restores it — rather than producing a document whose export the write then refuses.
 *
 * <p>The ceiling is lowered here to a few bytes: what MySQL's default packet does to a 32 MiB export, without
 * building one. The same for the file a run produces: its ceiling is lowered to what the database keeps of its
 * signed package, and a run that fills it says why. That the real ceiling is what the server stores is {@code ReportRunQueueIntegrationTest}'s.
 */
@DisplayName("report runs, under the database's export and document ceilings")
class ReportExportCeilingRoutesTest extends ApiTestBase {

    @MockitoBean
    private ReportExecutor executor;

    @MockitoSpyBean
    private ReportExportCeiling ceiling;

    @Autowired
    private SettingsService settings;

    @Autowired
    private ReportWorker worker;

    @Autowired
    private AuditLogRepository auditLog;

    @Test
    @DisplayName("an export over it fails export_too_large, with the reason and the setting, and nothing runs")
    void refusedBeforeThePluginRuns() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        String governor = tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Payments " + System.nanoTime())))));
        long project = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Checkout")))));
        mvc.perform(authenticated(post("/api/v1/report-plugins"), governor)
                .contentType(MediaType.APPLICATION_JSON).content(write(ReportPluginsRoutesTest.manifest(
                        ReportRunsRoutesTest.IMAGE)))).andExpect(status().isCreated());
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/report-plugins/summary"), asCiso()))
                .andExpect(status().isOk());
        doReturn(new ProjectExportBounds(64, 100_000, 100_000)).when(ceiling).bounds();

        long runId = idOf(mvc.perform(authenticated(post("/api/v1/projects/" + project + "/reports"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("pluginId", "summary"))))
                .andExpect(status().isAccepted()));
        assertThat(worker.drain()).isOne();

        JsonNode run = json.readTree(mvc.perform(authenticated(get("/api/v1/projects/" + project + "/reports/" + runId),
                asAdmin())).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(run.at("/state").asText()).isEqualTo("failed");
        assertThat(run.at("/reason").asText()).isEqualTo("export_too_large");
        assertThat(run.at("/detail").asText()).contains("64 bytes").contains("max_allowed_packet").contains("160M");
        verify(executor, never()).render(any(), any());
        assertThat(auditLog.findAll()).filteredOn(entry -> AuditOperation.PROJECT_EXPORTED.wireName()
                .equals(entry.getOperationType())).isEmpty();
    }

    @Test
    @DisplayName("a file's ceiling is lowered to what the database keeps of its package; filled, the run says why")
    void outputCeilingLowered() throws Exception {
        long project = activated();
        doReturn(1024L).when(ceiling).outputBytes(anyLong());
        ArgumentCaptor<ReportPluginManifest> rendered = ArgumentCaptor.forClass(ReportPluginManifest.class);
        when(executor.render(rendered.capture(), any())).thenReturn(new ReportPluginRenderer.Outcome.Failed(
                ReportRunReason.OUTPUT_FULL, "Its output directory filled at 1024 bytes.", true));

        long runId = idOf(mvc.perform(authenticated(post("/api/v1/projects/" + project + "/reports"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("pluginId", "summary"))))
                .andExpect(status().isAccepted()));
        assertThat(worker.drain()).isOne();

        assertThat(rendered.getValue().maxOutputBytes()).as("the plugin's directory holds what the row can").isEqualTo(1024L);
        JsonNode run = json.readTree(mvc.perform(authenticated(get("/api/v1/projects/" + project + "/reports/" + runId),
                asAdmin())).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(run.at("/reason").asText()).isEqualTo("output_full");
        assertThat(run.at("/detail").asText()).contains("lowered from the manifest's").contains("max_allowed_packet")
                .contains("160M");
    }

    /** A project with the summary plugin switched on for it. */
    private long activated() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        String governor = tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Payments " + System.nanoTime())))));
        long project = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Checkout")))));
        mvc.perform(authenticated(post("/api/v1/report-plugins"), governor)
                .contentType(MediaType.APPLICATION_JSON).content(write(ReportPluginsRoutesTest.manifest(
                        ReportRunsRoutesTest.IMAGE)))).andExpect(status().isCreated());
        mvc.perform(authenticated(put("/api/v1/projects/" + project + "/report-plugins/summary"), asCiso()))
                .andExpect(status().isOk());
        return project;
    }

    private long idOf(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString()).path("id").asLong();
    }
}
