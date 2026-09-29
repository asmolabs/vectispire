package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.checklists.ProjectChecklistService;
import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MvcResult;

/**
 * A scan or an import is never failed by the checklists reacting to it (decision 0032, amendment "the
 * scans answer the lines they measure"): the reaction runs after their commit and whatever it throws is
 * the caller's to swallow — the agent is answered for the result it sent, the pipeline for the report it
 * deposited, and neither goes back to a queue or a retry.
 */
@DisplayName("a scan and an import stand when answering the checklist fails")
class ChecklistAutomaticAnswersFailureRoutesTest extends ApiTestBase {

    @MockitoSpyBean
    private ProjectChecklistService checklists;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private CoverageImportRepository coverageImports;

    private long project;
    private long repository;

    @BeforeEach
    void failingChecklists() throws Exception {
        doThrow(new IllegalStateException("the measurer is down")).when(checklists).answerFromEvidence(anyLong());
        long solution = json.readTree(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "S " + System.nanoTime()))))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).path("id").asLong();
        project = json.readTree(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", "Checkout"))))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).path("id").asLong();
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("https://example.invalid/checkout-" + System.nanoTime() + ".git");
        entity.setBranch("main");
        repository = repositories.save(entity).getId();
        mvc.perform(authenticated(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put(
                        "/api/v1/projects/" + project + "/repositories/" + repository), asAdmin()))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("an agent's result is accepted and the scan completed, the reaction's failure logged")
    void theScanCompletes() throws Exception {
        ScanEntity pending = new ScanEntity();
        pending.setRepoId(repository);
        pending.setBranch("main");
        pending.setStatus(ScanStatus.PENDING.wireName());
        pending.setCreatedAt(Instant.now());
        pending.setFindingsCount(0);
        pending.setNewIssuesCount(0);
        pending.setResolvedIssuesCount(0);
        pending.setAttempts(0);
        scans.save(pending);
        String agent = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"agent-" + System.nanoTime() + "\", \"max_concurrent\": 1}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("secret").asText();
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent))
                .andReturn();
        long scanId = json.readTree(mvc.perform(asyncDispatch(started)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).path("scanId").asLong();

        mvc.perform(post("/api/v1/agent/jobs/" + scanId + "/result")
                        .header("Authorization", "Bearer " + agent)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"secrets\":[], \"duration\":\"PT1S\"}"))
                .andExpect(status().isOk());

        verify(checklists).answerFromEvidence(repository);
        ScanEntity scan = scans.findById(scanId).orElseThrow();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
        assertThat(scan.getAttempts()).as("not handed back to the queue").isEqualTo(1);
        assertThat(scan.getClaimedBy()).isNull();
    }

    @Test
    @DisplayName("a coverage report is recorded and answered 201, the reaction's failure logged")
    void theImportStands() throws Exception {
        JsonNode key = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "ci-" + System.nanoTime(), "scopes", List.of("report_import")))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("slug", "ledger-ci");
        source.put("name", "Ledger CI");
        source.put("api_key_id", key.path("key").path("id").asText());
        source.put("project_id", project);
        source.put("kinds", List.of("coverage"));
        mvc.perform(authenticated(post("/api/v1/sarif-sources"), tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER,
                        false)).contentType(MediaType.APPLICATION_JSON).content(write(source)))
                .andExpect(status().isCreated());

        mvc.perform(post("/api/v1/repositories/" + repository + "/coverage-imports?format=jacoco")
                        .header("Authorization", "Bearer " + key.path("secret").asText())
                        .contentType(MediaType.APPLICATION_XML)
                        .content(ReportImportRoutesTest.JACOCO.getBytes(StandardCharsets.UTF_8)))
                .andExpect(status().isCreated());

        verify(checklists).answerFromEvidence(repository);
        assertThat(coverageImports.findAll()).hasSize(1);
    }
}
