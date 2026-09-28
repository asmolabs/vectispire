package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * What a scan examined, from an agent's result body to the scan's detail — through the real routes,
 * the real mapper and the real database (decision 0032, §6).
 *
 * <p>The agent's body is JSON: an absent step is a missing key, an empty one {@code []}, and the
 * distinction has already been lost once on the wire (an {@code Optional} no module could write). This
 * sends both and reads what the detail says.
 */
@DisplayName("what a scan examined, through the routes")
class ScanExaminationRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Test
    @DisplayName("an agent's result records the steps that produced, and leaves out the one that failed")
    void theAgentsResultIsRecorded() throws Exception {
        long repository = repository();
        queue(repository);
        String agent = agent();
        long scanId = claim(agent).path("scanId").asLong();

        // Secrets ran and found nothing, the IaC step ran and found one; the dependency step failed,
        // so its key is missing — absent, not empty — and source analysis was never asked.
        String result = """
                {"secrets":[],
                 "iac":[{"checkId":"CKV_AWS_20","checkName":"S3 not public","file":"main.tf","line":4}],
                 "failures":[{"step":"dependencies","reason":"the matcher exited with 1"}],
                 "duration":"PT3S"}
                """;
        mvc.perform(post("/api/v1/agent/jobs/" + scanId + "/result")
                        .header("Authorization", "Bearer " + agent)
                        .contentType(MediaType.APPLICATION_JSON).content(result))
                .andExpect(status().isOk());

        mvc.perform(authenticated(get("/api/v1/scans/" + scanId), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scan.status").value("completed"))
                .andExpect(jsonPath("$.examinedTypes", Matchers.contains("iac", "secret")));
        assertThat(scans.findById(scanId).orElseThrow().getExaminedTypes()).isEqualTo("iac,secret");
    }

    @Test
    @DisplayName("a scan from before the column says its examination is unknown: null, not an empty list")
    void aScanFromBeforeIsUnknown() throws Exception {
        ScanEntity before = scan(repository(), ScanStatus.COMPLETED);
        before.setExaminedTypes(null);
        long unknown = scans.save(before).getId();
        ScanEntity nothing = scan(repository(), ScanStatus.FAILED);
        nothing.setExaminedTypes("");
        long none = scans.save(nothing).getId();

        String unknownBody = mvc.perform(authenticated(get("/api/v1/scans/" + unknown), asAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        // Present and null — a missing key would leave a client to guess which of the two it means.
        assertThat(json.readTree(unknownBody).has("examinedTypes")).isTrue();
        assertThat(json.readTree(unknownBody).get("examinedTypes").isNull()).isTrue();

        mvc.perform(authenticated(get("/api/v1/scans/" + none), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.examinedTypes").isArray())
                .andExpect(jsonPath("$.examinedTypes").isEmpty());
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/examined-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private static ScanEntity scan(long repositoryId, ScanStatus status) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(0);
        return scan;
    }

    private void queue(long repositoryId) {
        scans.save(scan(repositoryId, ScanStatus.PENDING));
    }

    private String agent() throws Exception {
        JsonNode answer = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"agent-" + System.nanoTime() + "\", \"max_concurrent\": 1}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        return answer.get("secret").asText();
    }

    private JsonNode claim(String agent) throws Exception {
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent))
                .andReturn();
        return json.readTree(mvc.perform(asyncDispatch(started)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }
}
