package com.asmolabs.zanshin.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.Issues;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the Threat Intelligence feed routes")
class ThreatIntelFeedRoutesTest extends ApiTestBase {

    @Autowired
    private Issues issuesRepo;

    @Test
    @DisplayName("synchronizes threat intelligence and reclassifies matching issues as KEV")
    void syncsThreatIntelAndUpdatesIssues() throws Exception {
        String adminToken = asAdmin();

        // 1. Create an issue with Log4Shell CVE that is initially not marked as KEV
        IssueEntity issue = new IssueEntity();
        issue.setType("sca");
        issue.setIdentifier("CVE-2021-44228");
        issue.setFingerprint("sha256-test-log4j-cve");
        issue.setPackageName("log4j-core");
        issue.setSource("trivy");
        issue.setSeverity("CRITICAL");
        issue.setState("open");
        issue.setKev(false);
        issue.setEpssScore(0.10);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTriageStatus("untriaged");
        issue = issuesRepo.save(issue);

        assertThat(issue.isKev()).isFalse();

        // 2. Query initial status
        mvc.perform(authenticated(get("/api/v1/threat-intel/status"), adminToken))
                .andExpect(status().isOk());

        // 3. Trigger threat intel sync
        mvc.perform(authenticated(post("/api/v1/threat-intel/sync"), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SYNCED"))
                .andExpect(jsonPath("$.totalKev").value(10))
                .andExpect(jsonPath("$.backlogUpdatedCount").isNumber());

        // 4. Verify issue was automatically upgraded to KEV and EPSS updated
        IssueEntity updated = issuesRepo.findById(issue.getId()).orElseThrow();
        assertThat(updated.isKev()).isTrue();
        assertThat(updated.getEpssScore()).isGreaterThan(0.90);
    }
}
