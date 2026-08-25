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

    @Test
    @DisplayName("processes Jira webhook for False Positive and auto-triages issue")
    void processesJiraWebhook() throws Exception {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-jira-webhook-test");
        issue.setIdentifier("CVE-2026-9999");
        issue.setType("vulnerability");
        issue.setSeverity("HIGH");
        issue.setState("open");
        issue.setTriageStatus("under_review");
        issue.setTicketRef("SEC-99");
        issue.setTicketUrl("https://jira.company.com/browse/SEC-99");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);

        String jiraPayload = """
                {
                    "webhookEvent": "jira:issue_updated",
                    "issue": {
                        "key": "SEC-99",
                        "fields": {
                            "status": { "name": "Closed" },
                            "resolution": { "name": "False Positive" }
                        }
                    },
                    "user": {
                        "displayName": "Security Lead Dev"
                    },
                    "comment": {
                        "body": "Not applicable in our isolated microservice context."
                    }
                }
                """;

        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jiraPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.matched").value(true))
                .andExpect(jsonPath("$.ticketRef").value("SEC-99"));

        IssueEntity updated = issues.findByTicketRefOrIid("SEC-99").orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals("not_affected", updated.getTriageStatus());
        org.junit.jupiter.api.Assertions.assertEquals("vulnerable_code_not_in_execute_path", updated.getTriageJustification());
    }

    @Test
    @DisplayName("processes GitLab webhook for issue close")
    void processesGitLabWebhook() throws Exception {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-gitlab-webhook-test");
        issue.setIdentifier("CVE-2026-8888");
        issue.setType("vulnerability");
        issue.setSeverity("HIGH");
        issue.setState("open");
        issue.setTriageStatus("under_review");
        issue.setTicketRef("#105");
        issue.setTicketUrl("https://gitlab.com/group/proj/-/issues/105");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);

        String gitlabPayload = """
                {
                    "object_kind": "issue",
                    "object_attributes": {
                        "iid": 105,
                        "title": "CVE-2026-8888 (wontfix)",
                        "state": "closed",
                        "description": "Won't fix because risk accepted by architecture board."
                    },
                    "user": {
                        "username": "lead_sec"
                    }
                }
                """;

        mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(gitlabPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.matched").value(true))
                .andExpect(jsonPath("$.ticketRef").value("105"));

        IssueEntity updated = issues.findByTicketRefOrIid("105").orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals("not_affected", updated.getTriageStatus());
    }
}
