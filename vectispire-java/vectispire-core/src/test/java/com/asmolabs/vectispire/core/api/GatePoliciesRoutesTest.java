package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Storing the rules a build is judged against.
 *
 * <p><b>The routes under test are the half that was missing.</b> {@code t_gate_policy} was read
 * from the first release — resolution, versioning, per-target scope, all of it — and written by
 * nothing, so every install ran on the built-in default and no test could tell, because each
 * half was correct on its own. These assertions are about the join: what is stored is what the
 * verdict applies.
 */
@DisplayName("storing a gate policy")
class GatePoliciesRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Test
    @DisplayName("a stored global policy is what the verdict applies")
    void theStoredPolicyDecides() throws Exception {
        long target = repository("https://example.invalid/global.git");
        // A medium: below the built-in threshold, so the gate is green before anything is stored.
        issue(target, "CVE-MEDIUM", Severity.MEDIUM);

        mvc.perform(gate(target)).andExpect(jsonPath("$.passed").value(true));

        mvc.perform(authenticated(put("/api/v1/gate/policies/global"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(policy("medium", true, false, false, false, "Tightened for the audit."))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(1));

        // The whole point of the feature: what an administrator saved changes what a pipeline is
        // told, and the verdict names the version it applied.
        mvc.perform(gate(target))
                .andExpect(jsonPath("$.passed").value(false))
                .andExpect(jsonPath("$.policy.source").value("global"))
                .andExpect(jsonPath("$.policy.version").value(1));
    }

    @Test
    @DisplayName("a target's own policy beats the global one")
    void theTargetOverridesTheGlobal() throws Exception {
        long strict = repository("https://example.invalid/strict.git");
        long lenient = repository("https://example.invalid/lenient.git");
        issue(strict, "CVE-S", Severity.LOW);
        issue(lenient, "CVE-L", Severity.LOW);

        store("global", null, policy("high", true, false, false, false, null));
        store("repository", strict, policy("low", true, false, false, false, "This one ships to customers."));

        mvc.perform(gate(strict))
                .andExpect(jsonPath("$.passed").value(false))
                .andExpect(jsonPath("$.policy.source").value("target"));

        // Untouched by its neighbour's override — the scope is the target, not the installation.
        mvc.perform(gate(lenient))
                .andExpect(jsonPath("$.passed").value(true))
                .andExpect(jsonPath("$.policy.source").value("global"));
    }

    @Test
    @DisplayName("\"none\" switches the severity rule off instead of failing everything")
    void noneMeansNoThreshold() throws Exception {
        long target = repository("https://example.invalid/kev-only.git");
        issue(target, "CVE-NOISE", Severity.CRITICAL);

        store("global", null, policy("none", true, false, false, false, "Actively exploited only."));

        // The reading that had to be got right: an absent threshold is UNKNOWN to `Severity.of`,
        // and UNKNOWN ranks below everything — `isAtLeast(UNKNOWN)` holds for every issue. Read
        // that way, the policy that switches the rule *off* fails every build, and the verdict
        // blames a threshold nobody set.
        mvc.perform(gate(target))
                .andExpect(jsonPath("$.passed").value(true))
                .andExpect(jsonPath("$.policy.failOnSeverity").doesNotExist());

        mvc.perform(authenticated(get("/api/v1/gate/policies"), asAdmin()))
                .andExpect(jsonPath("$.policies[?(@.kind == 'global')].fail_on_severity")
                        .value(org.hamcrest.Matchers.hasItem(org.hamcrest.Matchers.nullValue())));
    }

    @Test
    @DisplayName("saving again versions the policy rather than editing it")
    void savingVersions() throws Exception {
        long target = repository("https://example.invalid/versioned.git");

        store("repository", target, policy("high", true, false, false, false, "First."));
        store("repository", target, policy("medium", true, false, false, false, "Tightened."));

        // Only the newest is active — the unique index says so — and its number says how many
        // decisions preceded it. A build that failed in March failed under version 1, and the
        // row that judged it is still there.
        mvc.perform(authenticated(get("/api/v1/gate/policies"), asAdmin()))
                .andExpect(jsonPath("$.policies.length()").value(1))
                .andExpect(jsonPath("$.policies[0].version").value(2))
                .andExpect(jsonPath("$.policies[0].fail_on_severity").value("medium"))
                .andExpect(jsonPath("$.policies[0].note").value("Tightened."));
    }

    @Test
    @DisplayName("removing an override makes the target inherit again, and only once")
    void removingRestoresInheritance() throws Exception {
        long target = repository("https://example.invalid/reverted.git");
        issue(target, "CVE-R", Severity.LOW);

        store("global", null, policy("high", true, false, false, false, null));
        store("repository", target, policy("low", true, false, false, false, null));
        mvc.perform(gate(target)).andExpect(jsonPath("$.passed").value(false));

        mvc.perform(authenticated(delete("/api/v1/gate/policies/repository/" + target), asAdmin()))
                .andExpect(status().isNoContent());

        mvc.perform(gate(target))
                .andExpect(jsonPath("$.passed").value(true))
                .andExpect(jsonPath("$.policy.source").value("global"));

        // Not 204 twice: the same answer for "removed" and "there was nothing there" is how a
        // stale screen convinces somebody they undid something.
        mvc.perform(authenticated(delete("/api/v1/gate/policies/repository/" + target), asAdmin()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("an unreadable severity is refused, not stored")
    void aTypoIsRefused() throws Exception {
        // "hgh" reads as UNKNOWN, which ranks last: stored, it would be a gate that fails
        // everything under a name nobody typed.
        mvc.perform(authenticated(put("/api/v1/gate/policies/global"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(policy("hgh", true, false, false, false, null))))
                .andExpect(status().isBadRequest());

        // And a flag left out is refused rather than defaulted: this route replaces a policy
        // whole, so an omitted field would reinstate a built-in under a version number that
        // says somebody chose it.
        mvc.perform(authenticated(put("/api/v1/gate/policies/global"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fail_on_severity\":\"high\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("a policy for a target that does not exist is refused")
    void anUnknownTargetIsRefused() throws Exception {
        mvc.perform(authenticated(put("/api/v1/gate/policies/repository/999999"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(policy("high", true, false, false, false, null))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("an ordinary account may ask for a verdict and may not decide one")
    void readingIsNotDeciding() throws Exception {
        long target = repository("https://example.invalid/reader.git");

        mvc.perform(authenticated(post("/api/v1/gate"), asReader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"repository_id\":" + target + "}"))
                .andExpect(status().isOk());

        // The reason the write side is its own controller: a pipeline's API key asks for a
        // verdict on every build, and that must never be the same permission as changing what
        // the verdict means.
        mvc.perform(authenticated(put("/api/v1/gate/policies/global"), asReader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(policy("none", false, false, false, false, null))))
                .andExpect(status().isForbidden());

        mvc.perform(authenticated(get("/api/v1/gate/policies"), asReader()))
                .andExpect(status().isForbidden());
    }

    private void store(String kind, Long id, Map<String, Object> policy) throws Exception {
        String path = id == null ? "/api/v1/gate/policies/global" : "/api/v1/gate/policies/" + kind + "/" + id;
        mvc.perform(authenticated(put(path), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(policy)))
                .andExpect(status().isOk());
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder gate(long repositoryId) {
        return authenticated(post("/api/v1/gate"), asAdmin())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"repository_id\":" + repositoryId + "}");
    }

    private static Map<String, Object> policy(
            String failOnSeverity, boolean kev, boolean fixable, boolean triaged, boolean aiReview, String note) {

        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("fail_on_severity", failOnSeverity);
        body.put("fail_on_kev", kev);
        body.put("fixable_only", fixable);
        body.put("include_triaged", triaged);
        body.put("include_ai_review", aiReview);
        body.put("note", note);
        return body;
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void issue(long repoId, String identifier, Severity severity) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
