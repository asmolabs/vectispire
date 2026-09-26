package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.Scans;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
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

        // 3. The badge, once published — and only once published. It used to be served under the
        //    repository's id to anyone at all, which is how a caller with no account could read
        //    the grade of every repository here. `BadgeRoutesTest` owns that regression; this
        //    keeps the rendering itself covered from the screen that produces it.
        String published = mvc.perform(
                        authenticated(post("/api/v1/scorecards/repositories/" + repo.getId() + "/badge"), adminToken))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        mvc.perform(get(json.readTree(published).path("url").asText()))
                .andExpect(status().isOk())
                .andExpect(content().contentType("image/svg+xml"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("<svg")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("security grade")));
    }
}
