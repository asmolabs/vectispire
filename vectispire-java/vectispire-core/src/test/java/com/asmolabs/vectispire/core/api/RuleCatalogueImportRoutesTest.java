package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.rules.RuleCatalogue;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.rules.RuleCatalogueFetcher;
import com.asmolabs.vectispire.core.rules.RuleSetLosesIssuesException;
import com.asmolabs.vectispire.core.rules.persistence.SemgrepRuleSetEntity;
import com.asmolabs.vectispire.core.rules.persistence.SemgrepRuleSetRepository;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

/**
 * Importing the upstream catalogue leaves the rules that duplicate gitleaks out unless asked for.
 *
 * <p><b>Why they are left out.</b> The secrets step runs gitleaks with its default rules, and
 * {@code generic/secrets/gitleaks/} is those same rules for Semgrep, as are the files of {@code
 * generic/secrets/security/} that {@link RuleCatalogue#GITLEAKS_COVERED_SECURITY_RULES} names. Imported,
 * every leaked key comes back twice — a {@code secret} issue and a {@code sast} one, separate issues
 * because the type is in the fingerprint — and triaging the secret leaves its twin open, failing the gate
 * and counting in the score. The rest of {@code generic/secrets/security/} stays: it looks for things
 * gitleaks' defaults do not.
 *
 * <p>The fetcher is a spy whose clone is replaced by a fixed archive; the preview, the selection, the
 * store, the audit entry and the activation guard are the application's own.
 */
@DisplayName("importing the rule catalogue leaves the rules that duplicate gitleaks out unless asked")
class RuleCatalogueImportRoutesTest extends ApiTestBase {

    private static final String COMMIT = "f1d2b562b414783763fd02a6ed2736eaed622efa";

    /** One per class: the preview is kept ten minutes, so every test must see the same archive. */
    private static final String RUN = UUID.randomUUID().toString().substring(0, 8);

    private static final String PORT_RULE = "generic-api-key-" + RUN;
    private static final String PORT = RuleCatalogue.GITLEAKS_PORTS + "generic-api-key.yaml";
    private static final String COVERED = RuleCatalogue.SECURITY_SECRETS + "detected-twilio-api-key.yaml";
    private static final String SECURITY = RuleCatalogue.SECURITY_SECRETS + "detected-bcrypt-hash.yaml";
    private static final String PYTHON = "python/flask/sqli.yaml";

    private static final RuleCatalogueFetcher.Fetched FETCHED = new RuleCatalogueFetcher.Fetched(
            COMMIT,
            RuleCatalogue.describe(List.of(
                            new RuleCatalogue.Entry("LICENSE", "LGPL-2.1 with Commons Clause"),
                            new RuleCatalogue.Entry(PORT, rule(PORT_RULE)),
                            new RuleCatalogue.Entry(COVERED, rule("detected-twilio-api-key-" + RUN)),
                            new RuleCatalogue.Entry(SECURITY, rule("detected-bcrypt-hash-" + RUN)),
                            new RuleCatalogue.Entry(PYTHON, rule("sqli-" + RUN))),
                    "LGPL-2.1 with Commons Clause"),
            "licence-digest");

    @MockitoSpyBean
    private RuleCatalogueFetcher fetcher;

    @Autowired
    private SemgrepRuleSetRepository ruleSets;

    @Autowired
    private AuditLogRepository auditLogs;

    @Autowired
    private IssueRepository issues;

    @BeforeEach
    void aFixedArchive() {
        doReturn(FETCHED).when(fetcher).fetch();
    }

    @Test
    @DisplayName("the preview says how many of the generic rules duplicate gitleaks: the ports and the covered")
    void thePreviewCountsTheDuplicates() throws Exception {
        mvc.perform(authenticated(get("/api/v1/rule-sets/catalogue"), asCiso()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.languages.generic").value(3))
                .andExpect(jsonPath("$.gitleaksDuplicates").value(2));
    }

    @Test
    @DisplayName("by default: the duplicates are left out, the rest of generic/secrets/ kept, and the entry says so")
    void leftOutByDefault() throws Exception {
        long id = importing(Map.of());

        SemgrepRuleSetEntity stored = ruleSets.findById(id).orElseThrow();
        assertThat(stored.getFiles()).doesNotContain(PORT).doesNotContain(COVERED).contains(SECURITY).contains(PYTHON);
        assertThat(stored.getName()).doesNotContain("gitleaks");
        assertThat(entryOf(id)).contains("gitleaks duplicates left out.").contains("sha256 licence-digest");
    }

    @Test
    @DisplayName("an explicit false is the default")
    void falseIsTheDefault() throws Exception {
        long id = importing(Map.of("includeGitleaksDuplicates", false));

        assertThat(ruleSets.findById(id).orElseThrow().getFiles())
                .doesNotContain(PORT).doesNotContain(COVERED).contains(SECURITY);
    }

    @Test
    @DisplayName("on request: the duplicates come too, and the set's name and the entry say so")
    void includedOnRequest() throws Exception {
        long id = importing(Map.of("includeGitleaksDuplicates", true));

        SemgrepRuleSetEntity stored = ruleSets.findById(id).orElseThrow();
        assertThat(stored.getFiles()).contains(PORT).contains(COVERED).contains(SECURITY).contains(PYTHON);
        assertThat(stored.getName()).endsWith(" with gitleaks duplicates");
        assertThat(entryOf(id)).contains("gitleaks duplicates included on request.");
    }

    @Test
    @DisplayName("a selection that does not reach generic says nothing of the duplicates")
    void silentWhereTheDuplicatesAreNotInPlay() throws Exception {
        long id = importing(Map.of("languages", List.of("python"), "includeGitleaksDuplicates", true));

        assertThat(ruleSets.findById(id).orElseThrow().getName()).doesNotContain("gitleaks");
        assertThat(entryOf(id)).doesNotContain("gitleaks");
    }

    /**
     * <b>An installation that imported the ports before keeps them until it re-imports</b>, and the
     * re-import is where their issues would close. The activation guard is what makes that a decision:
     * the default set drops the port's rule, and its open issue is counted and refused like any other.
     */
    @Test
    @DisplayName("re-importing without the ports goes through the activation guard, which counts their issues")
    void reImportingWithoutThePortsIsGuarded() throws Exception {
        long withPorts = importing(Map.of("includeGitleaksDuplicates", true));
        Map<String, Object> accept = new HashMap<>();
        accept.put("acceptLosing", impactOf(withPorts).path("affectedIssues").asLong());
        mvc.perform(authenticated(post("/api/v1/rule-sets/" + withPorts + "/activate"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(accept)))
                .andExpect(status().isOk());
        openIssueOn(PORT_RULE);

        long withoutPorts = importing(Map.of());
        assertThat(impactOf(withoutPorts).path("losingIssues")).anySatisfy(rule ->
                assertThat(rule.asText()).isEqualTo(PORT_RULE));

        mvc.perform(authenticated(post("/api/v1/rule-sets/" + withoutPorts + "/activate"), asCiso()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:vectispire:problem:" + RuleSetLosesIssuesException.CAUSE));
        assertThat(ruleSets.findByIsActiveTrue()).map(SemgrepRuleSetEntity::getId).contains(withPorts);
    }

    /** Imports {@code generic} and {@code python} at the fixture's commit, with what {@code options} adds. */
    private long importing(Map<String, Object> options) throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("commit", COMMIT);
        body.put("languages", List.of("generic", "python"));
        body.put("licence_sha256", "licence-digest");
        body.putAll(options);
        String answer = mvc.perform(authenticated(post("/api/v1/rule-sets/catalogue"), asCiso())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(answer).path("id").asLong();
    }

    private com.fasterxml.jackson.databind.JsonNode impactOf(long id) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/rule-sets/" + id + "/impact"), asCiso()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private String entryOf(long id) {
        return auditLogs.findAll().stream()
                .filter(entry -> AuditOperation.RULE_SET_UPLOADED.name().equals(entry.getOperationType())
                        && String.valueOf(id).equals(entry.getResourceId()))
                .map(entry -> entry.getDescription())
                .findFirst()
                .orElseThrow();
    }

    private void openIssueOn(String ruleId) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-gitleaks-port-" + UUID.randomUUID());
        issue.setType("sast");
        issue.setIdentifier(ruleId);
        issue.setState("open");
        issue.setSeverity("LOW");
        issue.setTriageStatus("not_affected");
        issue.setKev(false);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private static String rule(String id) {
        return "rules:\n  - id: " + id + "\n    languages: [generic]\n    message: m\n    severity: INFO\n"
                + "    pattern: x\n";
    }
}
