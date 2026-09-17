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
 * who can get in, and asserts — rightly — that without a secret the door stays open, because
 * closing it would stop synchronisation on every existing deployment. It was right and silent
 * about what mattered. This one tests what can be done once inside, and it is what makes the
 * other's 200 acceptable.
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
    @DisplayName("with no secret, the decision goes to approval and never to \"not affected\"")
    void anonymousCannotSettle() throws Exception {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, "");
        IssueEntity issue = critical("fp-webhook-settle", "SEC-1234");

        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(FALSE_POSITIVE.formatted("SEC-1234")))
                .andExpect(status().isOk());

        IssueEntity after = issues.findById(issue.getId()).orElseThrow();

        // **`pending_approval`, and not `not_affected`.** The two resemble each other only in a
        // table: the second renders as `analysis.state = not_affected` in the signed documents, the
        // first renders there as "under review". That is the whole difference between recording
        // what a tracker says and publishing it in a human's place.
        assertThat(after.getTriageStatus())
                .as("an anonymous call cannot produce a \"not affected\" declaration")
                .isEqualTo("pending_approval");

        // **The author is the integration, not what the caller wrote.** The name came from the
        // payload and ended up in the audit log — tamper-evident, never purged — as the identity of
        // whoever decided. The hash chain protects that entry against a later modification; it does
        // not protect it against a lie dictated to it.
        assertThat(after.getTriagedBy())
                .as("the name the caller announces must not become an identity")
                .isEqualTo("JIRA_webhook");

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
