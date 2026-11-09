package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * The gate a pipeline asks about a target nobody examined.
 *
 * <p>It answered {@code passed: true}: the backlog of a target never scanned is empty, and an empty
 * backlog passes every policy — while the security screen, from the same data, called the target
 * never scanned. These go through the route as a pipeline does, because what a pipeline branches on
 * is the status, {@code passed} and the rule's spelling, and none of them is visible from the service.
 */
@DisplayName("the gate, on a target no scan examined")
class GateObservationRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Test
    @DisplayName("refuses a target never scanned, as a verdict and not as an error")
    void neverScanned() throws Exception {
        long target = repository("never");

        mvc.perform(gate("{\"repository_id\":" + target + "}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passed").value(false))
                .andExpect(jsonPath("$.evaluated").value(0))
                .andExpect(jsonPath("$.violations.length()").value(1))
                .andExpect(jsonPath("$.violations[0].rule").value("observation"))
                .andExpect(jsonPath("$.violations[0].issueId").value(Matchers.nullValue()))
                .andExpect(jsonPath("$.violations[0].reason").value(Matchers.containsString("never examined")));
    }

    @Test
    @DisplayName("refuses a target whose last scan failed, and says that is why")
    void lastScanFailed() throws Exception {
        long target = repository("failed");
        scan(target, ScanStatus.COMPLETED);
        scan(target, ScanStatus.FAILED);

        mvc.perform(gate("{\"repository_id\":" + target + "}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passed").value(false))
                .andExpect(jsonPath("$.violations[0].rule").value("observation"))
                .andExpect(jsonPath("$.violations[0].reason")
                        .value(Matchers.containsString("last scan of this target failed")));
    }

    @Test
    @DisplayName("refuses it whatever the request asks of the policy")
    void noRequestRelaxesIt() throws Exception {
        long target = repository("relaxed");

        // Every field a pipeline can send, at its laxest. The relaxations are refused as ever, and the
        // observation rule reads none of them.
        mvc.perform(gate("{\"repository_id\":" + target + ",\"fail_on_severity\":null,\"fail_on_kev\":false,"
                        + "\"fixable_only\":true,\"include_triaged\":false,\"include_ai_review\":false,"
                        + "\"include_plugins\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passed").value(false))
                .andExpect(jsonPath("$.violations[0].rule").value("observation"));
    }

    @Test
    @DisplayName("passes the same target once a scan has completed")
    void examined() throws Exception {
        long target = repository("examined");
        scan(target, ScanStatus.FAILED);
        scan(target, ScanStatus.COMPLETED);

        mvc.perform(gate("{\"repository_id\":" + target + "}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passed").value(true))
                .andExpect(jsonPath("$.violations.length()").value(0));
    }

    @Test
    @DisplayName("is recorded in the register as a refusal")
    void recorded() throws Exception {
        long target = repository("recorded");

        mvc.perform(gate("{\"repository_id\":" + target + "}")).andExpect(status().isOk());

        mvc.perform(authenticated(get("/api/v1/gate/verdicts"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdicts[?(@.target_id == " + target + ")].passed").value(Matchers.contains(false)))
                .andExpect(jsonPath("$.verdicts[?(@.target_id == " + target + ")].violations").value(Matchers.contains(1)));
    }

    @Test
    @DisplayName("is failing on the security screen, with the same violation")
    void theScreenAgrees() throws Exception {
        long target = repository("screen");

        mvc.perform(authenticated(get("/api/v1/security/overview"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targets[?(@.targetId == " + target + ")].passed").value(Matchers.contains(false)))
                .andExpect(jsonPath("$.targets[?(@.targetId == " + target + ")].observation")
                        .value(Matchers.contains("never_scanned")))
                .andExpect(jsonPath("$.targets[?(@.targetId == " + target + ")].verdict.violations[0].rule")
                        .value(Matchers.contains("observation")));
    }

    private MockHttpServletRequestBuilder gate(String body) {
        return authenticated(post("/api/v1/gate"), asAdmin()).contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/observation-" + name + "-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    /** Scans are written oldest first: "newest" is the highest identifier, as everywhere it is read. */
    private void scan(long repositoryId, ScanStatus status) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scans.save(scan);
    }
}
