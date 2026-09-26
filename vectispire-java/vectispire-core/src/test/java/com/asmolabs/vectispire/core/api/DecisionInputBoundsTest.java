package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.compliance.persistence.ControlDeclarations;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicies;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.Issues;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * The text and the dates a decision carries.
 *
 * <p>A comment, a note or a justification lands in a {@code text} column, which MySQL caps at 64 KB;
 * a date lands in a {@code DATETIME}, which ends in the year 9999. Past either the write failed as a
 * 500 — invisible on SQLite, which this suite runs on, so the assertion is the status. A review date
 * had a lower bound and no upper one, an extension could run into the past, and a review without an
 * outcome answered with a NullPointerException.
 */
@DisplayName("the bounds of a decision")
class DecisionInputBoundsTest extends ApiTestBase {

    private static final String TOO_LONG = "c".repeat(BoundedText.TEXT_MAX + 1);

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private ControlDeclarations declarations;

    @Autowired
    private GatePolicies policies;

    @Test
    @DisplayName("a triage comment past the text ceiling is a 400, alone or in bulk")
    void aTriageCommentIsBounded() throws Exception {
        long id = issue("CVE-TEXT-1", TriageStatus.UNDER_REVIEW);
        String admin = asAdmin();

        assertThat(send(admin, post("/api/v1/issues/" + id + "/triage"),
                        Map.of("status", "affected", "comment", TOO_LONG)))
                .isEqualTo(400);
        assertThat(send(admin, post("/api/v1/issues/triage"),
                        Map.of("ids", List.of(id), "status", "affected", "comment", TOO_LONG)))
                .isEqualTo(400);
        assertThat(issues.findById(id).orElseThrow().getTriageStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
    }

    @Test
    @DisplayName("a review delay past ten years is a 400, and ten years is accepted")
    void aReviewDelayIsBounded() throws Exception {
        long id = issue("CVE-DAYS-1", TriageStatus.UNDER_REVIEW);
        String admin = asAdmin();

        assertThat(send(admin, post("/api/v1/issues/" + id + "/triage"),
                        Map.of("status", "affected", "expires_in_days", 3651)))
                .isEqualTo(400);
        assertThat(send(admin, post("/api/v1/issues/" + id + "/triage"),
                        Map.of("status", "affected", "expires_in_days", Integer.MAX_VALUE)))
                .isEqualTo(400);
        assertThat(send(admin, post("/api/v1/issues/" + id + "/triage"),
                        Map.of("status", "affected", "expires_in_days", 3650)))
                .isEqualTo(200);
    }

    @Test
    @DisplayName("an exception review needs an outcome, and an extension runs forward and not beyond ten years")
    void anExceptionReviewIsValidated() throws Exception {
        long id = issue("CVE-REVIEW-1", TriageStatus.NOT_AFFECTED);
        String ciso = asCiso();
        String path = "/api/v1/exceptions/" + id + "/reviews";

        assertThat(send(ciso, post(path), Map.of("comment", "looked at it"))).as("no outcome").isEqualTo(400);
        assertThat(send(ciso, post(path), Map.of("outcome", "EXTENDED",
                        "new_expiry", Instant.now().minus(Duration.ofDays(1)).toString())))
                .as("an extension into the past")
                .isEqualTo(400);
        assertThat(send(ciso, post(path), Map.of("outcome", "EXTENDED",
                        "new_expiry", Instant.now().plus(Duration.ofDays(3660)).toString())))
                .as("an extension past ten years")
                .isEqualTo(400);
        assertThat(send(ciso, post(path), Map.of("outcome", "CONFIRMED", "comment", TOO_LONG)))
                .as("a comment past the text ceiling")
                .isEqualTo(400);
        assertThat(issues.findById(id).orElseThrow().getTriageExpiresAt()).isNull();

        Instant extended = Instant.now().plus(Duration.ofDays(90));
        assertThat(send(ciso, post(path), Map.of("outcome", "EXTENDED", "new_expiry", extended.toString())))
                .isEqualTo(200);
        assertThat(issues.findById(id).orElseThrow().getTriageExpiresAt()).isNotNull();
    }

    @Test
    @DisplayName("a declaration names a control of its framework, and its fields fit their columns")
    void aDeclarationIsValidated() throws Exception {
        String ciso = asCiso();
        Map<String, Object> valid = Map.of(
                "applicability", "APPLICABLE", "implementation", "IMPLEMENTED", "evidence_source", "VECTISPIRE");

        assertThat(send(ciso, put("/api/v1/compliance/soa/ISO_27001/ISO-A.99.99"), valid))
                .as("a control the catalogue does not name is absent")
                .isEqualTo(404);
        String path = "/api/v1/compliance/soa/ISO_27001/ISO-A.8.8";
        assertThat(send(ciso, put(path), with(valid, "owner", "o".repeat(256)))).isEqualTo(400);
        assertThat(send(ciso, put(path), with(valid, "justification", TOO_LONG))).isEqualTo(400);
        assertThat(send(ciso, put(path), with(valid, "review_due_at",
                        Instant.now().plus(Duration.ofDays(3660)).toString())))
                .isEqualTo(400);
        assertThat(send(ciso, put(path), with(valid, "review_due_at",
                        Instant.now().minus(Duration.ofDays(3660)).toString())))
                .isEqualTo(400);
        assertThat(declarations.findAll()).isEmpty();

        assertThat(send(ciso, put(path), with(valid, "review_due_at",
                        Instant.now().plus(Duration.ofDays(365)).toString())))
                .isEqualTo(200);
    }

    @Test
    @DisplayName("an upstream VEX statement past the ceiling is imported clipped, not refused half-way")
    void aVendorStatementIsClipped() throws Exception {
        long id = issue("CVE-2024-7777", TriageStatus.UNDER_REVIEW);
        String document = """
                {
                  "@context": "https://openvex.dev/ns/v0.2.0",
                  "@id": "https://vendor.example.com/vex/long",
                  "author": "Verbose Vendor",
                  "timestamp": "2026-08-23T00:00:00Z",
                  "version": 1,
                  "statements": [
                    {
                      "vulnerability": { "name": "CVE-2024-7777" },
                      "status": "not_affected",
                      "justification": "component_not_present",
                      "impact_statement": "%s"
                    }
                  ]
                }
                """.formatted("s".repeat(BoundedText.TEXT_MAX + 500));

        int status = mvc.perform(authenticated(post("/api/v1/vex/ingest"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(document))
                .andReturn().getResponse().getStatus();

        assertThat(status).isEqualTo(200);
        IssueEntity triaged = issues.findById(id).orElseThrow();
        assertThat(triaged.getTriageStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
        assertThat(triaged.getTriageComment()).startsWith("Upstream VEX statement by Verbose Vendor").hasSize(BoundedText.TEXT_MAX);
    }

    @Test
    @DisplayName("a gate policy note past the text ceiling is a 400")
    void aPolicyNoteIsBounded() throws Exception {
        String admin = asAdmin();
        Map<String, Object> policy = Map.of(
                "fail_on_severity", "high", "fail_on_kev", true, "fixable_only", false,
                "include_triaged", false, "include_ai_review", false);

        assertThat(send(admin, put("/api/v1/gate/policies/global"), with(policy, "note", TOO_LONG)))
                .isEqualTo(400);
        assertThat(policies.findAll()).isEmpty();
        assertThat(send(admin, put("/api/v1/gate/policies/global"), with(policy, "note", "Tightened.")))
                .as("the same policy with a note that fits")
                .isEqualTo(200);
    }

    private long issue(String identifier, TriageStatus status) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + identifier + ".git");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(status.wireName());
        if (status == TriageStatus.NOT_AFFECTED) {
            issue.setTriageJustification("component_not_present");
        }
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }

    private static Map<String, Object> with(Map<String, Object> base, String key, Object value) {
        Map<String, Object> copy = new HashMap<>(base);
        copy.put(key, value);
        return copy;
    }

    private int send(String token, MockHttpServletRequestBuilder request, Map<String, ?> body) throws Exception {
        return mvc.perform(authenticated(request, token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andReturn().getResponse().getStatus();
    }
}
