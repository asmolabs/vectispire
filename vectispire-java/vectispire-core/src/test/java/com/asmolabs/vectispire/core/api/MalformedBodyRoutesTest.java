package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.IssueTickets;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.inventory.LicenseGovernanceService;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Bodies that are well-formed JSON and still malformed requests.
 *
 * <p>Each of these answered 500: a {@code null} dereferenced somewhere past the controller, or a
 * value the database refused at the write. A malformed request is the caller's to fix, and a 500
 * tells them the opposite.
 */
@DisplayName("malformed bodies")
class MalformedBodyRoutesTest extends ApiTestBase {

    @Autowired
    private Issues issues;

    @Autowired
    private IssueTickets tickets;

    @Autowired
    private LicenseGovernanceService licences;

    @Test
    @DisplayName("a bulk triage selecting a null identifier is a 400")
    void aNullIdentifierInABulkTriage() throws Exception {
        long id = issue("CVE-NULL-1");

        MvcResult result = send(asAdmin(), post("/api/v1/issues/triage"),
                "{\"ids\":[" + id + ", null], \"status\":\"affected\"}");

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        // The wording is the assertion: without the guard, Spring Data's own argument check
        // answered 400 too, in a sentence about a repository.
        assertThat(result.getResponse().getContentAsString()).contains("Every selected issue needs an identifier");
        assertThat(issues.findById(id).orElseThrow().getTriageStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
    }

    @Test
    @DisplayName("a licence policy with missing sets or null entries is stored as the empty policy it means")
    void aLicencePolicyWithNulls() throws Exception {
        String admin = asAdmin();

        assertThat(send(admin, put("/api/v1/licenses/policy"), "{}").getResponse().getStatus()).isEqualTo(200);
        assertThat(licences.getPolicy().disallowedCategories()).isEmpty();

        MvcResult result = send(admin, put("/api/v1/licenses/policy"),
                "{\"disallowedCategories\":[\"FORBIDDEN\"],"
                        + "\"explicitlyAllowedLicenses\":[\" mit \",null,\"\"],"
                        + "\"explicitlyDisallowedLicenses\":null}");

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        LicensePolicy stored = licences.getPolicy();
        assertThat(stored.explicitlyAllowedLicenses())
                .as("trimmed and in capitals, so it matches the upper-cased licence it is compared with")
                .containsExactly("MIT");
        assertThat(stored.explicitlyDisallowedLicenses()).isEmpty();
        assertThat(stored.isCompliant("mit", com.asmolabs.vectispire.common.domain.licenses.LicenseRiskCategory.FORBIDDEN))
                .isTrue();

        // A null category never reaches the service: the HTTP layer's reader refuses a null enum
        // element itself. A 400 either way, which is the point — never the 500 it used to be.
        assertThat(send(admin, put("/api/v1/licenses/policy"), "{\"disallowedCategories\":[null]}")
                        .getResponse().getStatus())
                .isEqualTo(400);
    }

    @Test
    @DisplayName("a licence entry holding a comma is a 400, since the list is stored comma-joined")
    void aLicenceWithAComma() throws Exception {
        int status = send(asAdmin(), put("/api/v1/licenses/policy"),
                "{\"explicitlyAllowedLicenses\":[\"MIT,GPL-3.0\"]}").getResponse().getStatus();

        assertThat(status).isEqualTo(400);
        assertThat(licences.getPolicy().explicitlyAllowedLicenses()).doesNotContain("GPL-3.0");
    }

    @Test
    @DisplayName("a ticket link with a blank key, a key past 128 or a URL past 512 characters is a 400")
    void aTicketLinkIsBounded() throws Exception {
        long id = issue("CVE-TICKET-1");
        String admin = asAdmin();
        String path = "/api/v1/issues/" + id + "/tickets";

        assertThat(link(admin, path, "  ", "https://jira.example.com/browse/SEC-1")).isEqualTo(400);
        assertThat(link(admin, path, "K".repeat(129), "https://jira.example.com/browse/SEC-1")).isEqualTo(400);
        assertThat(link(admin, path, "SEC-1", "https://jira.example.com/" + "u".repeat(500))).isEqualTo(400);
        assertThat(link(admin, path, "SEC-1", " ")).isEqualTo(400);
        assertThat(tickets.findByIssueIdOrderByCreatedAtDesc(id)).isEmpty();

        assertThat(link(admin, path, " SEC-1 ", "https://jira.example.com/browse/SEC-1")).isEqualTo(201);
        assertThat(tickets.findByIssueIdOrderByCreatedAtDesc(id)).singleElement()
                .satisfies(ticket -> assertThat(ticket.getTicketKey()).isEqualTo("SEC-1"));
    }

    private int link(String token, String path, String key, String url) throws Exception {
        return send(token, post(path), write(Map.of("provider", "jira", "ticketKey", key, "ticketUrl", url)))
                .getResponse().getStatus();
    }

    private long issue(String identifier) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-" + identifier);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }

    private MvcResult send(String token, MockHttpServletRequestBuilder request, String body) throws Exception {
        return mvc.perform(authenticated(request, token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn();
    }
}
