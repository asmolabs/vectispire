package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.tickets.TicketingWebhookService;
import com.asmolabs.vectispire.core.tickets.persistence.WebhookDeliveryRepository;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.ResultActions;

/**
 * The inbound ticket webhook of a tracker whose integration is disabled (decision 0040 §3, owner's decision of
 * 2026-10-13): authenticated as ever, then answered 200 and ignored — never a 409, which the tracker would retry until
 * GitLab disabled the webhook, leaving it broken once the tracker is switched back on.
 *
 * <p>Through the real controller, over a Jira false-positive delivery that an enabled tracker queues for approval:
 * the issue's triage is what tells applied from ignored. {@code t_integration} is put back as it was found after each
 * case ({@link IntegrationRows}).
 */
@DisplayName("the ticket webhook of a disabled tracker")
class TrackerWebhookSuspensionRoutesTest extends ApiTestBase {

    private static final String SECRET = "s3cr3t-suspended-tracker";
    private static final String WEBHOOK = "/api/v1/tickets/webhook/jira";
    private static final Integration JIRA = Integration.of(TicketProvider.JIRA);

    private static final String FALSE_POSITIVE = """
            {"issue":{"key":"%s","fields":{
                "status":{"name":"Closed"},
                "resolution":{"name":"False Positive"}}},
             "user":{"displayName":"Security lead"},
             "webhookEvent":"jira:issue_updated"}""";

    @Autowired
    private Integrations integrations;

    @Autowired
    private SettingsService settings;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private WebhookDeliveryRepository deliveries;

    @Autowired
    private JdbcTemplate jdbc;

    private IntegrationRows rows;

    @BeforeEach
    void authenticated() {
        rows = IntegrationRows.remember(jdbc);
        settings.set(Setting.TICKET_WEBHOOK_SECRET, SECRET);
    }

    @AfterEach
    void putBack() {
        rows.putBack();
    }

    @Test
    @DisplayName("a delivery is answered 200 ignored_integration_disabled and changes nothing; re-enabled, the same body is applied")
    void ignoredThenApplied() throws Exception {
        IssueEntity issue = issue("fp-suspended-webhook", "SEC-4401");
        String body = FALSE_POSITIVE.formatted("SEC-4401");
        integrations.switchTo(JIRA, false, "test");

        deliver(body)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.matched").value(false))
                .andExpect(jsonPath("$.actionTaken").value(startsWith("ignored_integration_disabled: the tracker.jira")))
                .andExpect(jsonPath("$.actionTaken").value(org.hamcrest.Matchers.containsString(
                        "PUT /api/v1/integrations/tracker.jira/enabled")));

        IssueEntity after = issues.findById(issue.getId()).orElseThrow();
        assertThat(after.getTriageStatus()).as("no triage is queued").isEqualTo("under_review");
        assertThat(after.getTriagedBy()).isNull();
        assertThat(deliveries.count()).as("nothing is remembered of an ignored body, the replay table included")
                .isZero();

        integrations.switchTo(JIRA, true, "test");

        deliver(body)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.matched").value(true))
                .andExpect(jsonPath("$.issueId").value(issue.getId()));
        assertThat(issues.findById(issue.getId()).orElseThrow().getTriageStatus())
                .as("the body ignored while suspended is acted on once it is enabled again")
                .isEqualTo("pending_approval");
    }

    @Test
    @DisplayName("a delivery without the secret is still refused while the tracker is disabled, and learns nothing of it")
    void unauthenticatedIsStillRefused() throws Exception {
        IssueEntity issue = issue("fp-suspended-webhook-anon", "SEC-4402");
        integrations.switchTo(JIRA, false, "test");

        mvc.perform(post(WEBHOOK)
                        .header("X-Vectispire-Token", "not-the-secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(FALSE_POSITIVE.formatted("SEC-4402")))
                .andExpect(status().isUnauthorized())
                // A refusal is a problem document since 0.11.1, its reason in `detail`.
                .andExpect(jsonPath("$.detail").value("Webhook authentication failed"));

        settings.set(Setting.TICKET_WEBHOOK_SECRET, "");
        deliver(FALSE_POSITIVE.formatted("SEC-4402")).andExpect(status().isForbidden());

        assertThat(issues.findById(issue.getId()).orElseThrow().getTriageStatus()).isEqualTo("under_review");
    }

    @Test
    @DisplayName("the suspension is logged once over several deliveries, and its end once")
    void loggedOncePerSuspension() throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger(TicketingWebhookService.class);
        ListAppender<ILoggingEvent> captured = new ListAppender<>();
        captured.start();
        logger.addAppender(captured);
        try {
            // An applied delivery first, so that a suspension another case left unended reads as ended here.
            deliver(FALSE_POSITIVE.formatted("SEC-4499"));
            captured.list.clear();

            integrations.switchTo(JIRA, false, "test");
            for (int delivery = 0; delivery < 3; delivery++) {
                deliver(FALSE_POSITIVE.formatted("SEC-450" + delivery)).andExpect(status().isOk());
            }
            assertThat(captured.list).filteredOn(event -> event.getFormattedMessage().contains("is disabled"))
                    .singleElement()
                    .satisfies(event -> assertThat(event.getFormattedMessage()).contains("tracker.jira"));

            integrations.switchTo(JIRA, true, "test");
            for (int delivery = 0; delivery < 2; delivery++) {
                deliver(FALSE_POSITIVE.formatted("SEC-451" + delivery)).andExpect(status().isOk());
            }
            assertThat(captured.list).filteredOn(event -> event.getFormattedMessage().contains("enabled again"))
                    .singleElement()
                    .satisfies(event -> assertThat(event.getFormattedMessage()).contains("tracker.jira"));
            assertThat(captured.list).filteredOn(event -> event.getFormattedMessage().contains("is disabled"))
                    .hasSize(1);
        } finally {
            logger.detachAppender(captured);
        }
    }

    private ResultActions deliver(String body) throws Exception {
        return mvc.perform(post(WEBHOOK)
                .header("X-Vectispire-Token", SECRET)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private IssueEntity issue(String fingerprint, String ticketRef) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint(fingerprint);
        issue.setIdentifier("CVE-2021-44228");
        issue.setType("vulnerability");
        issue.setSeverity("CRITICAL");
        issue.setState("open");
        issue.setTriageStatus("under_review");
        issue.setTicketRef(ticketRef);
        issue.setFirstSeenAt(Instant.parse("2026-09-01T10:00:00Z"));
        issue.setLastSeenAt(Instant.parse("2026-09-01T10:00:00Z"));
        issue.setTimesSeen(1);
        return issues.save(issue);
    }
}
