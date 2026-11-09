package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

@DisplayName("the ticketing routes")
class TicketingRoutesTest extends ApiTestBase {

    @org.springframework.beans.factory.annotation.Autowired
    private com.asmolabs.vectispire.core.settings.SettingsService settings;

    @Autowired
    private IssueRepository issues;

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
    @DisplayName("processes Jira webhook for False Positive and queues the decision for approval")
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

        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_WEBHOOK_SECRET, "jira-shared");
        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", "jira-shared")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jiraPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.matched").value(true))
                .andExpect(jsonPath("$.ticketRef").value("SEC-99"));

        // **These two cases asserted `not_affected`, and that was the defect they described.** A
        // tracker is not an approver, signed or not; "the tracker said false positive" could
        // therefore not remain a conclusion. The justification is still recorded:
        // what changes is not what the tracker says but who publishes it. See
        // `TicketWebhookCannotSettleTest` for the property itself.
        IssueEntity updated = issues.findByTicketRefOrIid("SEC-99").getFirst();
        org.junit.jupiter.api.Assertions.assertEquals("pending_approval", updated.getTriageStatus());
        org.junit.jupiter.api.Assertions.assertEquals("vulnerable_code_not_in_execute_path", updated.getTriageJustification());
    }

    @Test
    @DisplayName("syncs every issue carrying the ticket — one Jira key on two findings — rather than answering 500")
    void syncsEveryIssueCarryingTheTicket() throws Exception {
        long first = carrying("SEC-77", "fp-shared-ticket-1").getId();
        long second = carrying("SEC-77", "fp-shared-ticket-2").getId();
        String payload = """
                {"webhookEvent":"jira:issue_updated",
                 "issue":{"key":"SEC-77","fields":{"status":{"name":"Closed"},"resolution":{"name":"False Positive"}}},
                 "user":{"displayName":"Security Lead Dev"},
                 "comment":{"body":"Not reachable in either service."}}""";

        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_WEBHOOK_SECRET, "jira-shared");
        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", "jira-shared")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.matched").value(true))
                .andExpect(jsonPath("$.issueId").value(first))
                .andExpect(jsonPath("$.issueIds.length()").value(2))
                .andExpect(jsonPath("$.issueIds[0]").value(first))
                .andExpect(jsonPath("$.issueIds[1]").value(second));

        for (long id : new long[] {first, second}) {
            IssueEntity queued = issues.findById(id).orElseThrow();
            org.junit.jupiter.api.Assertions.assertEquals("pending_approval", queued.getTriageStatus());
            org.junit.jupiter.api.Assertions.assertEquals("not_affected", queued.getTriageRequestedStatus());
        }
    }

    @Test
    @DisplayName("a GitLab iid matches the reference stored with and without its #, both synced")
    void anIidMatchesBothSpellings() throws Exception {
        long hashed = carrying("#205", "fp-iid-hashed").getId();
        long bare = carrying("205", "fp-iid-bare").getId();
        // References attached without a URL: the integration's repository is what scopes the number.
        String payload = """
                {"object_kind":"issue","user":{"username":"dev"},"project":{"path_with_namespace":"group/proj"},
                 "object_attributes":{"iid":205,"state":"closed","title":"False positive: not used","description":""}}""";

        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_WEBHOOK_SECRET, "gitlab-shared");
        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROVIDER, "gitlab");
        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROJECT, "group/proj");
        try {
            mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                            .header("X-Gitlab-Token", "gitlab-shared")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(payload))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.issueIds.length()").value(2))
                    .andExpect(jsonPath("$.issueIds[0]").value(hashed))
                    .andExpect(jsonPath("$.issueIds[1]").value(bare));
        } finally {
            settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROVIDER, "none");
            settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROJECT, "");
        }
    }

    @Test
    @DisplayName("a GitHub or GitLab number is a repository's: an event about another repository's issue 12 moves nothing")
    void anotherRepositorysNumberMovesNothing() throws Exception {
        // Matched on the bare number, an event about issue 306 of any repository on the forge moved
        // every finding whose ticket was 306 somewhere else.
        IssueEntity withUrl = carrying("#306", "fp-other-repo-url");
        withUrl.setTicketUrl("https://gitlab.com/group/proj/-/issues/306");
        issues.save(withUrl);
        IssueEntity withoutUrl = carrying("306", "fp-other-repo-bare");
        String payload = """
                {"object_kind":"issue","user":{"username":"dev"},"project":{"path_with_namespace":"someone/else"},
                 "object_attributes":{"iid":306,"state":"closed","title":"False positive","description":"",
                 "url":"https://gitlab.com/someone/else/-/issues/306"}}""";

        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_WEBHOOK_SECRET, "gitlab-shared");
        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROVIDER, "gitlab");
        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROJECT, "group/proj");
        try {
            mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                            .header("X-Gitlab-Token", "gitlab-shared")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(payload))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.matched").value(false));
        } finally {
            settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROVIDER, "none");
            settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_PROJECT, "");
        }

        org.junit.jupiter.api.Assertions.assertEquals("under_review", issues.findById(withUrl.getId()).orElseThrow().getTriageStatus());
        org.junit.jupiter.api.Assertions.assertEquals("under_review", issues.findById(withoutUrl.getId()).orElseThrow().getTriageStatus());
    }

    private IssueEntity carrying(String ticketRef, String fingerprint) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint(fingerprint);
        issue.setIdentifier("CVE-2026-7777");
        issue.setType("vulnerability");
        issue.setSeverity("HIGH");
        issue.setState("open");
        issue.setTriageStatus("under_review");
        issue.setTicketRef(ticketRef);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue);
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
                        "description": "Won't fix because risk accepted by architecture board.",
                        "url": "https://gitlab.com/group/proj/-/issues/105"
                    },
                    "user": {
                        "username": "lead_sec"
                    }
                }
                """;

        settings.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_WEBHOOK_SECRET, "gitlab-shared");
        mvc.perform(post("/api/v1/tickets/webhook/gitlab")
                        .header("X-Gitlab-Token", "gitlab-shared")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(gitlabPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.matched").value(true))
                .andExpect(jsonPath("$.ticketRef").value("105"));

        IssueEntity updated = issues.findByTicketRefOrIid("105").getFirst();
        org.junit.jupiter.api.Assertions.assertEquals("pending_approval", updated.getTriageStatus());
    }
}
