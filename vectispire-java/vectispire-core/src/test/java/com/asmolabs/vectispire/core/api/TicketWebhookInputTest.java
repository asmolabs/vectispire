package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.SettingsService;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * What the tracker's webhook may send, and how much of it.
 *
 * <p>The tracker is a machine nobody here can correct: what it says is clipped to fit, never
 * refused, because a refusal drops the decision it carries.
 */
@DisplayName("what the ticket webhook accepts")
class TicketWebhookInputTest extends ApiTestBase {

    private static final String SECRET = "s3cr3t-partage";

    private static final String WITH_COMMENT = """
            {"issue":{"key":"%s","fields":{
                "status":{"name":"Closed"},
                "resolution":{"name":"False Positive"}}},
             "comment":{"body":"%s"},
             "webhookEvent":"jira:issue_updated"}""";

    @Autowired
    private Issues issues;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("a tracker comment past the ceiling is recorded clipped, and the decision still queued")
    void aLongCommentIsClipped() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, SECRET);
        IssueEntity issue = critical("fp-webhook-long", "SEC-4242");

        int status = mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", SECRET)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(WITH_COMMENT.formatted("SEC-4242", "w".repeat(BoundedText.TEXT_MAX + 100))))
                .andReturn().getResponse().getStatus();

        assertThat(status).isEqualTo(200);
        IssueEntity after = issues.findById(issue.getId()).orElseThrow();
        assertThat(after.getTriageStatus()).isEqualTo("pending_approval");
        assertThat(after.getTriageComment()).hasSize(BoundedText.TEXT_MAX);
    }

    IssueEntity critical(String fingerprint, String ticketRef) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint(fingerprint);
        issue.setIdentifier("CVE-2021-44228");
        issue.setType("vulnerability");
        issue.setSeverity("critical");
        issue.setState("open");
        issue.setTriageStatus("under_review");
        issue.setTicketRef(ticketRef);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue);
    }
}
