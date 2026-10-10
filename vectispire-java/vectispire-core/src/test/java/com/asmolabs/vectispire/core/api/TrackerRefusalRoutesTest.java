package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.tickets.WebhookAuthenticity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * A tracker's refusal is an accepted exposure, not a clearance (decision 0041).
 *
 * <p>A ticket closed as "Won't Fix" was queued as {@code not_affected} with "inline mitigations already exist",
 * and GitHub's {@code not_planned} as a false positive "not in the execute path": statements about the product
 * the tracker never made, which the signed VEX documents carried once approved.
 */
@DisplayName("a tracker's refusal")
class TrackerRefusalRoutesTest extends ApiTestBase {

    private static final String SECRET = "shared-for-refusals";

    private static final String JIRA = """
            {"issue":{"key":"%s","fields":{
                "status":{"name":"Closed"},
                "resolution":{"name":"%s"}}},
             "user":{"displayName":"Team lead"},
             "comment":{"body":"Legacy module, retired next quarter."},
             "webhookEvent":"jira:issue_updated"}""";

    @Autowired
    private IssueRepository issues;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogRepository auditLog;

    @BeforeEach
    void secret() {
        settings.set(Setting.TICKET_WEBHOOK_SECRET, SECRET);
    }

    @Test
    @DisplayName("Won't Fix is queued as will_not_fix, with no justification and a proposed review date")
    void wontFixIsAnAcceptedRisk() throws Exception {
        String key = unique("SEC");
        IssueEntity issue = open("refusal-wontfix", key);

        jira(key, "Won't Fix");

        IssueEntity after = issues.findById(issue.getId()).orElseThrow();
        assertThat(after.getTriageStatus()).as("a tracker is not an approver").isEqualTo("pending_approval");
        assertThat(after.getTriageJustification())
                .as("no mitigation the tracker never mentioned").isNull();
        assertThat(after.getTriageExpiresAt()).isAfter(Instant.now().plus(Duration.ofDays(89)));
        assertThat(after.getTriageComment()).contains("Legacy module");
    }

    @Test
    @DisplayName("an explicit false positive is still queued as not_affected, with its justification")
    void aFalsePositiveIsAClaimAboutExposure() throws Exception {
        String key = unique("SEC");
        IssueEntity issue = open("refusal-fp", key);

        jira(key, "False Positive");

        IssueEntity after = issues.findById(issue.getId()).orElseThrow();
        assertThat(after.getTriageStatus()).isEqualTo("pending_approval");
        assertThat(after.getTriageJustification()).isEqualTo("vulnerable_code_not_in_execute_path");
    }

    @Test
    @DisplayName("GitHub's not_planned is a refusal, not a false positive")
    void notPlannedIsNotAFalsePositive() throws Exception {
        String number = String.valueOf(100_000 + System.nanoTime() % 900_000);
        IssueEntity issue = open("refusal-github", number);
        String body = """
                {"action":"closed","issue":{"number":%s,"state":"closed","state_reason":"not_planned",
                 "body":"We will not schedule this."},"sender":{"login":"maintainer"}}""".formatted(number);

        mvc.perform(post("/api/v1/tickets/webhook/github")
                        .header("X-Hub-Signature-256", "sha256=" + WebhookAuthenticity.hmacSha256Hex(SECRET, body))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk());

        IssueEntity after = issues.findById(issue.getId()).orElseThrow();
        assertThat(after.getTriageStatus()).isEqualTo("pending_approval");
        assertThat(after.getTriageJustification()).isNull();
    }

    @Test
    @DisplayName("a decision a person settled is not moved, and a contradiction is signalled")
    void aSettledDecisionStays() throws Exception {
        String key = unique("SEC");
        IssueEntity issue = open("refusal-settled", key);
        issue.setTriageStatus("not_affected");
        issue.setTriageJustification("component_not_present");
        issue.setTriagedBy("ciso");
        issues.save(issue);

        jira(key, "Won't Fix");

        IssueEntity after = issues.findById(issue.getId()).orElseThrow();
        assertThat(after.getTriageStatus()).isEqualTo("not_affected");
        assertThat(after.getTriageJustification()).isEqualTo("component_not_present");
        assertThat(after.getTriagedBy()).isEqualTo("ciso");
        assertThat(auditLog.findAll())
                .filteredOn(entry -> AuditOperation.TRIAGE_CONTRADICTED_BY_TRACKER.wireName()
                        .equals(entry.getOperationType()))
                .extracting(AuditLogEntity::getDescription)
                .anySatisfy(description -> assertThat(description).contains(key, "will_not_fix", "not_affected"));
    }

    @Test
    @DisplayName("a tracker agreeing with a settled decision is recorded, not signalled")
    void anAgreementIsNotAContradiction() throws Exception {
        String key = unique("SEC");
        IssueEntity issue = open("refusal-agrees", key);
        issue.setTriageStatus("will_not_fix");
        issue.setTriageExpiresAt(Instant.now().plus(Duration.ofDays(30)));
        issues.save(issue);

        jira(key, "Won't Fix");

        assertThat(issues.findById(issue.getId()).orElseThrow().getTriageStatus()).isEqualTo("will_not_fix");
        assertThat(auditLog.findAll())
                .filteredOn(entry -> String.valueOf(issue.getId()).equals(entry.getResourceId()))
                .extracting(AuditLogEntity::getOperationType)
                .doesNotContain(AuditOperation.TRIAGE_CONTRADICTED_BY_TRACKER.wireName())
                .contains(AuditOperation.TICKET_SYNCED.wireName());
    }

    private void jira(String key, String resolution) throws Exception {
        mvc.perform(post("/api/v1/tickets/webhook/jira")
                        .header("X-Vectispire-Token", SECRET)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JIRA.formatted(key, resolution)))
                .andExpect(status().isOk());
    }

    private static String unique(String prefix) {
        return prefix + "-" + (100_000 + System.nanoTime() % 900_000);
    }

    private IssueEntity open(String fingerprint, String ticketRef) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint(fingerprint + "-" + System.nanoTime());
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
