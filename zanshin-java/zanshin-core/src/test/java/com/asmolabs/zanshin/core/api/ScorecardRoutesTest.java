package com.asmolabs.zanshin.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.Scans;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the Security Scorecard and SVG Badge routes")
class ScorecardRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositoriesRepo;

    @Autowired
    private Scans scansRepo;

    @Autowired
    private Issues issuesRepo;

    @Test
    @DisplayName("computes repository security scorecard and serves public SVG badge")
    void computesScorecardAndRendersBadge() throws Exception {
        String adminToken = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/payment-service");
        repo.setUrl("https://github.com/corp/payment-service.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repo.getId());
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scansRepo.save(scan);

        // 1. Check clean repo -> Grade A+
        mvc.perform(authenticated(get("/api/v1/scorecards/repositories/" + repo.getId()), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.grade").value("A_PLUS"))
                .andExpect(jsonPath("$.score").value(100));

        // 2. Add an active KEV issue -> Grade D or F
        IssueEntity kevIssue = new IssueEntity();
        kevIssue.setRepoId(repo.getId());
        kevIssue.setType("cve");
        kevIssue.setSource("trivy");
        kevIssue.setSeverity("critical");
        kevIssue.setState("open");
        kevIssue.setFingerprint("fp-kev-1");
        kevIssue.setKev(true);
        kevIssue.setTriageStatus("untriaged");
        kevIssue.setFirstSeenAt(Instant.now());
        kevIssue.setLastSeenAt(Instant.now());
        issuesRepo.save(kevIssue);

        mvc.perform(authenticated(get("/api/v1/scorecards/repositories/" + repo.getId()), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openKevCount").value(1))
                .andExpect(jsonPath("$.openCriticalCount").value(1));

        // 3. Test public SVG badge endpoint (no token required)
        mvc.perform(get("/api/v1/scorecards/repositories/" + repo.getId() + "/badge.svg"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("image/svg+xml"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("<svg")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("security grade")));
    }
}
