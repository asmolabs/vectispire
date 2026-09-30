package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.rules.RuleSetLosesIssuesException;
import com.asmolabs.vectispire.core.rules.persistence.SemgrepRuleSetRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Activating a rule set, or returning to the bundled rules, refuses to resolve open issues unless the
 * caller names their number.
 *
 * <p>The context is shared with the rest of the suite, so another test's open SAST issues may be in
 * the backlog: every count here is read from the impact route rather than assumed, and each test's
 * own rule id is unique, which is what makes its loss certain.
 */
@DisplayName("a rule-set change that would resolve open issues is refused unless their number is accepted")
class RuleSetActivationLossRoutesTest extends ApiTestBase {

    private static final String PROBLEM = "urn:vectispire:problem:" + RuleSetLosesIssuesException.CAUSE;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private SemgrepRuleSetRepository ruleSets;

    @Autowired
    private AuditLogRepository auditLogs;

    /** The rule the baseline set holds and the next one drops, with an open issue on it. */
    private String rule;

    /** The set active at the start of each test, holding {@link #rule}. */
    private long baseline;

    @BeforeEach
    void aBaselineHoldingAnOpenIssue() throws Exception {
        rule = "loss-" + UUID.randomUUID();
        baseline = upload("baseline", rule);
        activateAccepting(baseline);
        openIssueOn(rule);
    }

    @Test
    @DisplayName("without acceptLosing: 409 with the count and the rules, and nothing changes")
    void refusedWithoutTheField() throws Exception {
        long next = upload("next", "kept-" + UUID.randomUUID());
        JsonNode impact = impactOf(next);
        long affected = impact.path("affectedIssues").asLong();
        assertThat(affected).isPositive();

        MvcResult refused = mvc.perform(authenticated(post("/api/v1/rule-sets/" + next + "/activate"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("note", "shown nothing"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(PROBLEM))
                .andExpect(jsonPath("$.affectedIssues").value(affected))
                .andReturn();

        assertThat(json.readTree(refused.getResponse().getContentAsString()).path("losingIssues"))
                .extracting(JsonNode::asText)
                .contains(rule);
        assertThat(detailOf(refused))
                .contains("resolves " + affected + " open issue(s)")
                .contains(rule)
                .contains("acceptLosing: " + affected);
        assertThat(activeId()).as("the set that was active stays active").isEqualTo(baseline);
        assertThat(openIssuesOn(rule)).isEqualTo(1);
        assertThat(activationsOf(next)).as("a refused activation writes no entry").isEmpty();
    }

    @Test
    @DisplayName("with acceptLosing equal to the count: activates, and the audit entry names the loss")
    void activatedWithTheExactCount() throws Exception {
        long next = upload("next", "kept-" + UUID.randomUUID());
        long affected = impactOf(next).path("affectedIssues").asLong();

        mvc.perform(authenticated(post("/api/v1/rule-sets/" + next + "/activate"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("acceptLosing", affected))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(next));

        assertThat(activeId()).isEqualTo(next);
        assertThat(activationsOf(next)).singleElement()
                .satisfies(entry -> assertThat(entry).contains("Accepted loss: " + affected + " open issue(s)"));
    }

    @Test
    @DisplayName("with a stale, a lower or a higher count: 409 with the current count")
    void refusedWithAStaleCount() throws Exception {
        long next = upload("next", "kept-" + UUID.randomUUID());
        long previewed = impactOf(next).path("affectedIssues").asLong();

        // A finding arrives between the preview and the click.
        openIssueOn(rule);

        MvcResult stale = mvc.perform(authenticated(post("/api/v1/rule-sets/" + next + "/activate"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("acceptLosing", previewed))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(PROBLEM))
                .andExpect(jsonPath("$.affectedIssues").value(previewed + 1))
                .andReturn();
        assertThat(detailOf(stale)).contains("You accepted " + previewed + "; the backlog reads " + (previewed + 1));

        mvc.perform(authenticated(post("/api/v1/rule-sets/" + next + "/activate"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("acceptLosing", previewed + 5))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.affectedIssues").value(previewed + 1));

        assertThat(activeId()).isEqualTo(baseline);
        assertThat(activationsOf(next)).isEmpty();
    }

    @Test
    @DisplayName("a change that resolves nothing activates as before, without the field")
    void noLossNeedsNoField() throws Exception {
        // Every rule that holds an open issue now, whoever seeded it, is kept: nothing can resolve.
        List<String> kept = new ArrayList<>();
        impactOf(upload("probe", "probe-" + UUID.randomUUID())).path("losingIssues").forEach(id -> kept.add(id.asText()));
        assertThat(kept).contains(rule);
        long next = upload("superset", kept.toArray(String[]::new));
        assertThat(impactOf(next).path("affectedIssues").asLong()).isZero();

        mvc.perform(authenticated(post("/api/v1/rule-sets/" + next + "/activate"), asCiso()))
                .andExpect(status().isOk());

        assertThat(activeId()).isEqualTo(next);
        assertThat(activationsOf(next)).singleElement()
                .satisfies(entry -> assertThat(entry).contains("No open issue resolves."));
    }

    @Test
    @DisplayName("returning to the bundled rules is refused the same way, and goes ahead on the exact count")
    void deactivationIsGuardedAlike() throws Exception {
        long affected = mvc.perform(authenticated(get("/api/v1/rule-sets/deactivate/impact"), asCiso()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()
                .transform(body -> readTree(body).path("affectedIssues").asLong());
        assertThat(affected).isPositive();

        mvc.perform(authenticated(post("/api/v1/rule-sets/deactivate"), asCiso()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value(PROBLEM))
                .andExpect(jsonPath("$.affectedIssues").value(affected))
                .andExpect(jsonPath("$.losingIssues[?(@ == '" + rule + "')]").exists());
        assertThat(activeId()).isEqualTo(baseline);

        mvc.perform(authenticated(post("/api/v1/rule-sets/deactivate"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("acceptLosing", affected))))
                .andExpect(status().isOk());
        assertThat(ruleSets.findByIsActiveTrue()).isEmpty();
        assertThat(auditLogs.findAll()).anySatisfy(entry -> {
            assertThat(entry.getOperationType()).isEqualTo(AuditOperation.RULE_SET_DEACTIVATED.name());
            assertThat(entry.getDescription()).contains("Accepted loss: " + affected + " open issue(s)");
        });
    }

    private long upload(String name, String... ruleIds) throws Exception {
        StringBuilder content = new StringBuilder("rules:\n");
        for (String id : ruleIds) {
            content.append("  - id: ").append(id).append('\n');
        }
        String body = mvc.perform(authenticated(post("/api/v1/rule-sets"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "name", name,
                                "files", List.of(Map.of("name", "rules.yaml", "content", content.toString()))))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return readTree(body).path("id").asLong();
    }

    private JsonNode impactOf(long id) throws Exception {
        return readTree(mvc.perform(authenticated(get("/api/v1/rule-sets/" + id + "/impact"), asCiso()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    /** Activates whatever the backlog holds now: the fixture's own step, accepting the loss it is told. */
    private void activateAccepting(long id) throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("acceptLosing", impactOf(id).path("affectedIssues").asLong());
        mvc.perform(authenticated(post("/api/v1/rule-sets/" + id + "/activate"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().isOk());
    }

    private void openIssueOn(String ruleId) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-rule-set-loss-" + UUID.randomUUID());
        issue.setType("sast");
        issue.setIdentifier(ruleId);
        issue.setState("open");
        issue.setSeverity("HIGH");
        issue.setTriageStatus("not_affected");
        issue.setKev(false);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private long openIssuesOn(String ruleId) {
        return issues.findAll().stream()
                .filter(issue -> ruleId.equals(issue.getIdentifier()) && "open".equals(issue.getState()))
                .count();
    }

    private Long activeId() {
        return ruleSets.findByIsActiveTrue().map(row -> row.getId()).orElse(null);
    }

    private List<String> activationsOf(long id) {
        return auditLogs.findAll().stream()
                .filter(entry -> AuditOperation.RULE_SET_ACTIVATED.name().equals(entry.getOperationType())
                        && String.valueOf(id).equals(entry.getResourceId()))
                .map(entry -> entry.getDescription())
                .toList();
    }

    private JsonNode readTree(String body) {
        try {
            return json.readTree(body);
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }
}
