package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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

@DisplayName("the security debt and remediation routes")
class SecurityDebtRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Test
    @DisplayName("calculates security debt and high impact fixes")
    void calculatesDebt() throws Exception {
        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("test-debt-repo");
        repo.setUrl("https://github.com/asmolabs/debt.git");
        repo.setBranch("main");
        repo = repositories.save(repo);

        IssueEntity issue1 = new IssueEntity();
        issue1.setFingerprint("fp-cve-1");
        issue1.setIdentifier("CVE-2023-1234");
        issue1.setType("vulnerability");
        issue1.setSeverity("critical");
        issue1.setState("open");
        issue1.setTriageStatus("UNTRIAGED");
        issue1.setPackageName("spring-core");
        issue1.setPackageVersion("5.3.0");
        issue1.setRepoId(repo.getId());
        issue1.setFilePath("pom.xml");
        issue1.setLine(15);
        issue1.setFirstSeenAt(Instant.now().minusSeconds(86400));
        issue1.setLastSeenAt(Instant.now());
        issues.save(issue1);

        IssueEntity issue2 = new IssueEntity();
        issue2.setFingerprint("fp-secret-1");
        issue2.setIdentifier("generic-api-key");
        issue2.setType("secret");
        issue2.setSeverity("high");
        issue2.setState("open");
        issue2.setTriageStatus("UNTRIAGED");
        issue2.setRepoId(repo.getId());
        issue2.setFilePath("src/main/resources/app.properties");
        issue2.setLine(5);
        issue2.setFirstSeenAt(Instant.now().minusSeconds(86400));
        issue2.setLastSeenAt(Instant.now());
        issues.save(issue2);

        mvc.perform(authenticated(get("/api/v1/remediation/debt"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalOpenIssues").value(org.hamcrest.Matchers.greaterThanOrEqualTo(2)))
                .andExpect(jsonPath("$.totalEstimatedHours").value(org.hamcrest.Matchers.greaterThan(0.0)))
                .andExpect(jsonPath("$.totalEstimatedPersonDays").value(org.hamcrest.Matchers.greaterThan(0.0)))
                .andExpect(jsonPath("$.topHighImpactFixes").isArray());

        mvc.perform(authenticated(get("/api/v1/remediation/high-impact-fixes"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }
}
