package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.audit.persistence.AuditLog;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * The small ones: a status that said the wrong thing, an audit entry filed under the wrong name, a
 * filter that matched nothing in silence.
 */
@DisplayName("the small input fixes")
class SmallInputFixesTest extends ApiTestBase {

    @Autowired
    private AuditLog auditLog;

    @Autowired
    private Issues issues;

    @Test
    @DisplayName("activating a rule set that does not exist is a 404, not a malformed request")
    void anAbsentRuleSetIsNotFound() throws Exception {
        int status = mvc.perform(authenticated(post("/api/v1/rule-sets/987654/activate"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andReturn().getResponse().getStatus();

        assertThat(status).isEqualTo(404);
    }

    @Test
    @DisplayName("a compliance report and an evidence bundle are audited as exports, not as model reviews")
    void exportsAreAuditedAsExports() throws Exception {
        String admin = asAdmin();
        assertThat(mvc.perform(authenticated(get("/api/v1/compliance/export.pdf"), admin))
                        .andReturn().getResponse().getStatus())
                .isEqualTo(200);
        assertThat(mvc.perform(authenticated(get("/api/v1/compliance/evidence-bundle.zip"), admin))
                        .andReturn().getResponse().getStatus())
                .isEqualTo(200);

        assertThat(auditLog.findAll())
                .filteredOn(entry -> "compliance".equals(entry.getResourceId())
                        || "evidence_vault".equals(entry.getResourceId()))
                .hasSize(2)
                .allSatisfy(entry -> assertThat(entry.getOperationType()).isEqualTo(AuditOperation.REPORT_EXPORTED.wireName()));
    }

    @Test
    @DisplayName("a ticket attached by hand is audited as a ticket link, not as an account change")
    void aTicketLinkIsAuditedAsOne() throws Exception {
        long id = issue();

        int status = mvc.perform(authenticated(post("/api/v1/issues/" + id + "/tickets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("provider", "jira", "ticketKey", "SEC-7",
                                "ticketUrl", "https://jira.example.com/browse/SEC-7"))))
                .andReturn().getResponse().getStatus();

        assertThat(status).isEqualTo(201);
        assertThat(auditLog.findAll())
                .filteredOn(entry -> String.valueOf(id).equals(entry.getResourceId()))
                .singleElement()
                .satisfies(entry -> assertThat(entry.getOperationType()).isEqualTo(AuditOperation.TICKET_LINKED.wireName()));
    }

    @Test
    @DisplayName("a framework is named however it is spelt, and an unknown one is a 400")
    void frameworksAreParsedLeniently() throws Exception {
        String admin = asAdmin();
        for (String spelling : new String[] {"iso-27001", "ISO_27001", "NIS2", "pci-dss"}) {
            assertThat(mvc.perform(authenticated(get("/api/v1/compliance/frameworks/" + spelling), admin))
                            .andReturn().getResponse().getStatus())
                    .as(spelling)
                    .isEqualTo(200);
        }
        assertThat(mvc.perform(authenticated(get("/api/v1/compliance/frameworks/hipaa"), admin))
                        .andReturn().getResponse().getStatus())
                .isEqualTo(400);
    }

    @Test
    @DisplayName("an issue filter naming no state, severity or type is a 400 rather than an empty page")
    void unknownFiltersAreRefused() throws Exception {
        issue();
        String admin = asAdmin();

        assertThat(list(admin, "state=opne")).isEqualTo(400);
        assertThat(list(admin, "severity=SEVERE")).isEqualTo(400);
        assertThat(list(admin, "type=vulnerabilities")).isEqualTo(400);

        assertThat(list(admin, "state=all")).isEqualTo(200);
        assertThat(list(admin, "severity=")).as("blank is no filter").isEqualTo(200);
        String page = mvc.perform(authenticated(get("/api/v1/issues?severity=HIGH&type=VULNERABILITY"), admin))
                .andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(page).get("total").asLong())
                .as("case aside, the filter matches the issue it names")
                .isEqualTo(1);
    }

    private int list(String token, String query) throws Exception {
        return mvc.perform(authenticated(get("/api/v1/issues?" + query), token)).andReturn().getResponse().getStatus();
    }

    private long issue() {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-small-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-0001");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
