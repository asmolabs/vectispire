package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.SettingsService;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * An anonymous door does not settle a triage.
 *
 * <p><b>The defect this closes, reproduced before it was fixed.</b> A {@code POST} with no
 * credential whatsoever — the route is {@code permitAll} in the filter chain, the handler carries
 * {@code @OpenToAnonymous}, and no secret is configured by default — moved a critical CVE to
 * {@code not_affected} with the justification {@code vulnerable_code_not_in_execute_path}. The
 * only barrier was guessing a ticket reference, something like {@code SEC-1234}.
 *
 * <p><b>What that reached.</b> Not a screen: {@code CycloneDxGeneratorService.mapAnalysis} renders
 * {@code not_affected} as the {@code analysis.state} of the same name, with its justification, in
 * signed CycloneDX, OpenVEX and CSAF documents handed to third parties. It is exactly the claim
 * this repository has already withdrawn once, by making the reachability analyser one-way, and the
 * invariant is written out as a comment directly above that function: "triage clears a component;
 * reachability does not". This door was the hole in it.
 *
 * <p><b>Why this case is not the same as {@code TicketWebhookAuthRoutesTest}.</b> That one tests
 * who can get in — and since 25 September, without a secret, nobody does. This one tests what can
 * be done once inside, which still matters: a secret establishes that the tracker sent the call,
 * not that anybody looked at the vulnerability.
 */
@DisplayName("un webhook anonyme ne peut pas clore un triage")
class TicketWebhookCannotSettleTest extends ApiTestBase {

    @Autowired
    private Issues issues;

    @Autowired
    private SettingsService settings;

    private static final String FALSE_POSITIVE = """
            {"issue":{"key":"%s","fields":{
                "status":{"name":"Closed"},
                "resolution":{"name":"False Positive"}}},
             "user":{"displayName":"Responsable Securite"},
             "webhookEvent":"jira:issue_updated"}""";

    @Test
    @DisplayName("with no secret, nothing is recorded at all")
    void anonymousCannotSettle() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "");
        IssueEntity issue = critical("fp-webhook-settle", "SEC-1234");

        // It used to be accepted, and the decision went to approval: better than "not affected",
        // still a stranger writing into the triage queue. The route is shut until a secret is set.
        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(FALSE_POSITIVE.formatted("SEC-1234")))
                .andExpect(status().isForbidden());

        assertThat(issues.findById(issue.getId()).orElseThrow().getTriageStatus()).isEqualTo("under_review");
    }

    @Test
    @DisplayName("an authenticated tracker's claimed author stays reported data, not an identity")
    void theAuthorIsTheIntegration() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "s3cr3t-partage");
        IssueEntity issue = critical("fp-webhook-author", "SEC-1235");

        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", "s3cr3t-partage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(FALSE_POSITIVE.formatted("SEC-1235")))
                .andExpect(status().isOk());

        IssueEntity after = issues.findById(issue.getId()).orElseThrow();
        // **The author is the integration, not what the caller wrote.** The name came from the
        // payload and ended up in the audit log — tamper-evident, never purged — as the identity of
        // whoever decided. The hash chain protects that entry against a later modification; it does
        // not protect it against a lie dictated to it.
        assertThat(after.getTriagedBy()).isEqualTo("JIRA_webhook");
        // It stays written, because it helps whoever investigates — but as reported data.
        assertThat(after.getTriageComment()).contains("Responsable Securite");
    }

    @Test
    @DisplayName("even with a verified secret: a tracker is not an approver")
    void aVerifiedTrackerIsStillNotAnApprover() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "s3cr3t-partage");
        IssueEntity issue = critical("fp-webhook-verified", "SEC-9876");

        // **The secret authenticates, it does not authorise.** It establishes that the call really
        // comes from the tracker; it does not establish that somebody looked at the vulnerability.
        // Making settlement depend on the secret would have moved the question rather than settled
        // it — and a tracker whose transitions are open to a whole company is not a control.
        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", "s3cr3t-partage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(FALSE_POSITIVE.formatted("SEC-9876")))
                .andExpect(status().isOk());

        assertThat(issues.findById(issue.getId()).orElseThrow().getTriageStatus())
                .isEqualTo("pending_approval");
    }

    @Test
    @DisplayName("a delivery replayed later is not acted on twice")
    void aReplayedDeliveryIsIgnored() throws Exception {
        // A signed delivery captured on the wire stayed valid for ever: sent again after an
        // approver had turned the decision down, it queued the same decision again.
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "s3cr3t-partage");
        IssueEntity issue = critical("fp-webhook-replay", "SEC-5555");
        String body = FALSE_POSITIVE.formatted("SEC-5555");

        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", "s3cr3t-partage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk());

        // An approver turns it down.
        IssueEntity rejected = issues.findById(issue.getId()).orElseThrow();
        rejected.setTriageStatus("under_review");
        issues.save(rejected);

        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", "s3cr3t-partage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.actionTaken")
                        .value("Delivery already processed"));

        assertThat(issues.findById(issue.getId()).orElseThrow().getTriageStatus()).isEqualTo("under_review");
    }

    private IssueEntity critical(String fingerprint, String ticketRef) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint(fingerprint);
        issue.setIdentifier("CVE-2021-44228");
        issue.setType("vulnerability");
        issue.setSeverity("CRITICAL");
        issue.setState("open");
        issue.setTriageStatus("under_review");
        issue.setTicketRef(ticketRef);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue);
    }
}
