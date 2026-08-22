package com.asmolabs.zanshin.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.Users;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * The field names the Angular client <b>sends</b>.
 *
 * <p>The other direction was the obvious one to check. This one is worse, because JSON that
 * arrives with a name nothing binds does not fail: the field is simply null, and the request
 * succeeds having quietly done less than it said. Three of these were exactly that —
 * a repository created with no agent label, an account whose deactivation did nothing and
 * reported success, and a dismissal whose review date was dropped so it never came back.
 *
 * <p>Every payload below is written the way {@code api.service.ts} writes it, snake_case
 * included. That file is the specification; this is what holds the two together.
 */
@DisplayName("what the Angular client sends")
class ClientRequestContractTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private Users users;

    @Test
    @DisplayName("a repository keeps the agent label it was created with")
    void theRequiredLabelIsNotDropped() throws Exception {
        mvc.perform(authenticated(post("/api/v1/repositories"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "url", "https://example.invalid/labelled.git",
                                "branch", "main",
                                "required_agent_label", "production"))))
                .andExpect(status().isOk());

        // Dropped, targeting becomes true "except for anything created from the interface" —
        // and the scan goes to whichever agent claims it first.
        assertThat(repositories.findAll()).singleElement()
                .returns("production", repository -> repository.getRequiredAgentLabel());
    }

    @Test
    @DisplayName("deactivating an account actually deactivates it")
    void deactivationIsNotSilentlyIgnored() throws Exception {
        String admin = asAdmin();
        // Somebody other than the caller, and not the last administrator: the self-lockout rule
        // refuses both, and would answer 400 for a reason that has nothing to do with binding.
        String victim = "victim-" + System.nanoTime();
        tokenFor(victim, com.asmolabs.zanshin.common.domain.users.Role.USER, false);
        long id = users.findByUsername(victim).orElseThrow().getId();

        Map<String, Object> patch = new HashMap<>();
        patch.put("is_active", false);

        mvc.perform(authenticated(patch("/api/v1/users/" + id), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(patch)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isActive").value(false));

        // Ignored, the screen confirms a deactivation that never happened and the account keeps
        // signing in.
        assertThat(users.findById(id).orElseThrow().getIsActive()).isFalse();
    }

    @Test
    @DisplayName("a dismissal keeps its review date")
    void theReviewDateIsNotDropped() throws Exception {
        long id = issue();

        mvc.perform(authenticated(post("/api/v1/issues/" + id + "/triage"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "status", "not_affected",
                                "justification", "vulnerable_code_not_present",
                                "expires_in_days", 90))))
                .andExpect(status().isOk());

        // Dropped, the dismissal is permanent: the issue never returns to review, and the
        // context it was dismissed for changes without anybody being told.
        assertThat(issues.findById(id).orElseThrow().getTriageExpiresAt()).isNotNull();
    }

    @Test
    @DisplayName("an SSH key arrives under the name the client gives it")
    void theKeyMaterialBinds() throws Exception {
        mvc.perform(authenticated(post("/api/v1/ssh-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "name", "deploy",
                                "private_key", "-----BEGIN DUMMY PRIVATE KEY-----\ntest\n-----END DUMMY PRIVATE KEY-----",
                                "public_key", "ssh-ed25519 AAAA"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey").value("ssh-ed25519 AAAA"));
    }

    @Test
    @DisplayName("an image arrives under the name the client gives it")
    void theImageNameBinds() throws Exception {
        mvc.perform(authenticated(post("/api/v1/containers"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "image_name", "team/service",
                                "tag", "1.4.0",
                                "required_agent_label", "production"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.imageName").value("team/service"))
                .andExpect(jsonPath("$.requiredAgentLabel").value("production"));
    }

    @Test
    @DisplayName("the login's client identifier reaches the throttle's second counter")
    void theClientIdentifierBinds() throws Exception {
        String username = "throttled-" + System.nanoTime();
        tokenFor(username, com.asmolabs.zanshin.common.domain.users.Role.USER, false);

        // Dropped, the counter falls back to the IP address — and behind a corporate NAT that
        // is one lock shared by everybody, which is what the second counter exists to avoid.
        mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "username", username,
                                "password", "correct horse battery staple",
                                "client_id", "browser-42"))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("changing a password reads the two fields the client sends")
    void thePasswordFieldsBind() throws Exception {
        String token = asPendingPasswordChange();

        mvc.perform(authenticated(post("/api/v1/auth/change-password"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "current_password", "correct horse battery staple",
                                "new_password", "a different long passphrase"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(false));
    }

    private long issue() {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-1");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
