package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the EPSS and CISA KEV prioritization routes")
class EpssRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositoriesRepo;

    @Autowired
    private Issues issuesRepo;

    @Test
    @DisplayName("retrieves EPSS fleet summary and priority rankings")
    void retrievesPriorities() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/auth-service");
        repo.setUrl("https://github.com/corp/auth-service.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repo.getId());
        issue.setType("sca");
        issue.setIdentifier("CVE-2021-44228");
        issue.setDescription("Remote Code Execution in Apache Log4j");
        issue.setSeverity("CRITICAL");
        issue.setCvssScore(10.0);
        issue.setKev(true);
        issue.setEpssScore(0.975);
        issue.setReachability("REACHABLE");
        issue.setState("open");
        issue.setTriageStatus("untriaged");
        issue.setFingerprint("fp-log4shell-test");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issuesRepo.save(issue);

        mvc.perform(authenticated(get("/api/v1/epss/priorities"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalVulnerabilities").isNumber())
                .andExpect(jsonPath("$.activeKevCount").isNumber())
                .andExpect(jsonPath("$.topPriorities[0].identifier").value("CVE-2021-44228"))
                .andExpect(jsonPath("$.topPriorities[0].priorityTier").value("CRITICAL_ARMED"))
                .andExpect(jsonPath("$.topPriorities[0].priorityScore").isNumber());

        mvc.perform(authenticated(get("/api/v1/epss/cve/CVE-2021-44228"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value("CVE-2021-44228"))
                .andExpect(jsonPath("$.isKev").value(true))
                .andExpect(jsonPath("$.epssScore").value(0.975));

        mvc.perform(authenticated(post("/api/v1/epss/sync"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SYNCED"));
    }
}
