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
import org.springframework.http.MediaType;

@DisplayName("the ticketing routes")
class TicketingRoutesTest extends ApiTestBase {

    @Autowired
    private Issues issues;

    @Test
    @DisplayName("creates and lists external issue tickets")
    void createsAndListsTickets() throws Exception {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-ticketing-test");
        issue.setIdentifier("CVE-2026-1234");
        issue.setType("vulnerability");
        issue.setSeverity("CRITICAL");
        issue.setState("open");
        issue.setTriageStatus("untriaged");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        IssueEntity savedIssue = issues.save(issue);

        String createJson = """
                {
                    "provider": "JIRA",
                    "ticketKey": "SEC-42",
                    "ticketUrl": "https://jira.company.com/browse/SEC-42"
                }
                """;

        mvc.perform(authenticated(post("/api/v1/issues/" + savedIssue.getId() + "/tickets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createJson))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.ticketKey").value("SEC-42"))
                .andExpect(jsonPath("$.provider").value("JIRA"));

        mvc.perform(authenticated(get("/api/v1/issues/" + savedIssue.getId() + "/tickets"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].ticketKey").value("SEC-42"));
    }
}
