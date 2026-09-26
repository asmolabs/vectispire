package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.settings.SettingsService;
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

    @Test
    @DisplayName("thirty refused deliveries from one address write two audit entries, not thirty")
    void refusalsAreAuditedSparingly() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, SECRET);
        long before = webhookEntries();

        for (int i = 0; i < 30; i++) {
            int status = mvc.perform(post("/api/v1/tickets/webhook/jira")
                            .header("X-Vectispire-Token", "wrong-" + i)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"attempt\":" + i + "}"))
                    .andReturn().getResponse().getStatus();
            assertThat(status).as("each refusal is still answered").isEqualTo(401);
        }

        assertThat(webhookEntries() - before)
                .as("the first refusal, and the one reaching the ceiling")
                .isEqualTo(2);
    }

    @Test
    @DisplayName("past the per-address ceiling a delivery is answered 429 before any work")
    void aFloodIsRefused() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "");
        // Sent until refused rather than exactly 301: the bucket refills greedily, five tokens a
        // second at the default, so a slow machine earns a few extra deliveries on the way. What
        // is pinned is that the first 300 pass and that the refusal comes shortly after.
        int sent = 0;
        String retryAfter = null;
        while (sent < 400) {
            var response = mvc.perform(post("/api/v1/tickets/webhook/github")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andReturn().getResponse();
            sent++;
            if (response.getStatus() == 429) {
                retryAfter = response.getHeader("Retry-After");
                break;
            }
        }

        assertThat(sent).as("deliveries sent until the first 429").isGreaterThan(300).isLessThan(400);
        assertThat(retryAfter).isNotBlank();
    }

    @Test
    @DisplayName("a body past a megabyte is answered 413, without reading it")
    void anOversizedBodyIsRefused() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, SECRET);
        byte[] body = new byte[1024 * 1024 + 1];
        java.util.Arrays.fill(body, (byte) ' ');

        int status = mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", SECRET)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn().getResponse().getStatus();

        assertThat(status).isEqualTo(413);
    }

    @Autowired
    private com.asmolabs.vectispire.core.repositories.AuditLog auditLog;

    private long webhookEntries() {
        return auditLog.findAll().stream().filter(entry -> "ticket_webhook".equals(entry.getResourceId())).count();
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
