package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The field names the unchanged Angular client reads.
 *
 * <p><b>These are not stylistic choices, they are a contract with code nobody is editing.</b>
 * The client's models were written against the NestJS API, and a port that renames a field
 * compiles, passes every other test, and blanks a screen. Each assertion below corresponds to a
 * line in {@code frontend/src/app/core/api.models.ts} — that file is the specification, and this
 * is what holds the two together until the client is regenerated from an OpenAPI document that
 * actually describes the shapes.
 *
 * <p>Every one of these was wrong when the comparison was first run.
 */
@DisplayName("what the Angular client reads")
class ClientContractTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private com.asmolabs.zanshin.core.repositories.Issues issues;

    @Test
    @DisplayName("a setting's default is called \"default\", not \"defaultValue\"")
    void theSettingsScreenFindsItsDefaults() throws Exception {
        // `default` is a Java keyword, so the field cannot carry that name and the annotation is
        // the only way. Without it every default on the settings screen renders blank.
        mvc.perform(authenticated(get("/api/v1/settings"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.settings[0].default").exists())
                .andExpect(jsonPath("$.settings[0].defaultValue").doesNotExist());
    }

    @Test
    @DisplayName("a posture names its target's kind and id, flattened")
    void theSecurityScreenCanTellARepositoryFromAnImage() throws Exception {
        seedRepository();

        // A sealed interface serializes with no discriminator: the first version sent
        // `"target": {"id": 1}`, from which no client can tell a repository from an image.
        mvc.perform(authenticated(get("/api/v1/security/overview"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targets[0].kind").value("repository"))
                .andExpect(jsonPath("$.targets[0].targetId").isNumber())
                .andExpect(jsonPath("$.targets[0].target").doesNotExist());
    }

    @Test
    @DisplayName("the observation is lowercase, as the client compares it")
    void theObservationMatchesWhatTheScreenCompares() throws Exception {
        seedRepository();

        // The screen does `observation === 'never_scanned'`. Against `NEVER_SCANNED` it matches
        // nothing and quietly renders its fallback, which reads as "everything is fine".
        mvc.perform(authenticated(get("/api/v1/security/overview"), asAdmin()))
                .andExpect(jsonPath("$.targets[0].observation").value("never_scanned"))
                // `built-in` with a hyphen: the screen matches it exactly to print "défaut",
                // and anything else is printed raw followed by a version — "built_in vnull".
                .andExpect(jsonPath("$.targets[0].policy.source").value("built-in"));
    }

    @Test
    @DisplayName("the last scan is flattened to two fields, absent when there is none")
    void theLastScanIsFlattened() throws Exception {
        seedRepository();

        mvc.perform(authenticated(get("/api/v1/security/overview"), asAdmin()))
                .andExpect(jsonPath("$.targets[0].lastScanAt").doesNotExist())
                .andExpect(jsonPath("$.targets[0].lastScan").doesNotExist())
                .andExpect(jsonPath("$.targets[0].observed").value(false));
    }

    @Test
    @DisplayName("the policy is two fields, not a policy inside a policy")
    void thePolicyIsNotNested() throws Exception {
        seedRepository();

        mvc.perform(authenticated(get("/api/v1/security/overview"), asAdmin()))
                // `version` is present and null for the built-in policy — the client types it
                // as `number | null` and shows "défaut" when there is none.
                .andExpect(jsonPath("$.targets[0].policy.version").doesNotExist())
                .andExpect(jsonPath("$.targets[0].policy.policy").doesNotExist())
                .andExpect(jsonPath("$.targets[0].policy.ignoredRelaxations").doesNotExist());
    }

    @Test
    @DisplayName("a violation names its rule, severity and package as the client reads them")
    void aViolationIsReadableByTheClientAndByAPipeline() throws Exception {
        long id = seedRepository();
        seedViolatingIssue(id);

        // This is the payload a build failure is explained by. The enum would have arrived as
        // `KEV` and `HIGH`, and the component as `packageName` — three fields, all compared
        // exactly, by a dashboard and by whatever a pipeline pipes this into.
        mvc.perform(authenticated(post("/api/v1/gate"), asAdmin())
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content(write(java.util.Map.of("repository_id", id))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passed").value(false))
                .andExpect(jsonPath("$.violations[0].rule").value("severity"))
                .andExpect(jsonPath("$.violations[0].severity").value("high"))
                .andExpect(jsonPath("$.violations[0].package").value("openssl"))
                .andExpect(jsonPath("$.violations[0].packageName").doesNotExist())
                .andExpect(jsonPath("$.counts_by_severity.high").value(1));
    }

    private void seedViolatingIssue(long repositoryId) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-1");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setPackageName("openssl");
        issue.setFirstSeenAt(java.time.Instant.now());
        issue.setLastSeenAt(java.time.Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private long seedRepository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/posture.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }
}
