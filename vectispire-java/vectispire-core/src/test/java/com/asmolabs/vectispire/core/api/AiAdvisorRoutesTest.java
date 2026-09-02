package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the AI Advisor and Explainer REST endpoints")
class AiAdvisorRoutesTest extends ApiTestBase {

    @Autowired
    private Issues issuesRepo;

    @Test
    @DisplayName("GET /api/v1/ai-advisor/status returns model status")
    void getsStatus() throws Exception {
        mvc.perform(authenticated(get("/api/v1/ai-advisor/status"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").isBoolean())
                .andExpect(jsonPath("$.selectedModel").isString());
    }

    @Test
    @DisplayName("POST /api/v1/ai-advisor/explain/cve/{cveId} returns deterministic advice for CVE")
    void explainsCve() throws Exception {
        mvc.perform(authenticated(
                post("/api/v1/ai-advisor/explain/cve/CVE-2021-44228?packageName=log4j-core&currentVersion=2.14.1&fixVersion=2.17.1"),
                asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.identifier").value("CVE-2021-44228"))
                .andExpect(jsonPath("$.summaryExplanation").value(org.hamcrest.Matchers.containsString("log4j-core")))
                .andExpect(jsonPath("$.remediation.suggestedVersion").value("2.17.1"));
    }

    @Test
    @DisplayName("POST /api/v1/ai-advisor/explain/issue/{issueId} explains existing issue entity")
    void explainsIssue() throws Exception {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("test-fingerprint-ai-advisor-001");
        issue.setType("vulnerability");
        issue.setIdentifier("CVE-2022-42889");
        issue.setPackageName("commons-text");
        issue.setPackageVersion("1.9");
        issue.setFixVersions("1.10.0");
        issue.setReachability("UNREACHABLE");
        issue.setState("open");
        issue.setSeverity("MEDIUM");
        issue.setTriageStatus("under_review");
        issue.setKev(false);
        issue.setEpssScore(0.05);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issue = issuesRepo.save(issue);

        mvc.perform(authenticated(post("/api/v1/ai-advisor/explain/issue/" + issue.getId()), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.identifier").value("CVE-2022-42889"))
                // La suggestion arrive pré-remplie devant la personne qui triage : elle ne peut pas
                // proposer une exonération déduite d'une corrélation de texte restée muette.
                .andExpect(jsonPath("$.vexSuggestion.status").value("under_investigation"))
                .andExpect(jsonPath("$.vexSuggestion.justification").doesNotExist());
    }
}
