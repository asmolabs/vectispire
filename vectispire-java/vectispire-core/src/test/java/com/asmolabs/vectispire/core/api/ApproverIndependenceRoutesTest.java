package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.AccountAdministrationRepository;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Under four-eyes, a triage is not approved by an account its requester administered recently (#126,
 * option 1).
 *
 * <p>The attack each case replays: an administrator makes the second identity — creates it, resets its
 * password, or gives it the role that approves — later asks for an exemption as an ordinary account, and
 * approves it under the name just made. Two names compared unequal, so four-eyes reported itself
 * satisfied. Each gesture is made through the route an administrator uses, so the record it leaves is the
 * one production leaves; the requester is then demoted by hand, the one step an attacker would take some
 * other way.
 */
@DisplayName("an approver the requester administered recently")
class ApproverIndependenceRoutesTest extends ApiTestBase {

    private static final String PASSWORD = "a-temporary-password-of-length";

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private UserRepository users;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AccountAdministrationRepository gestures;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("is refused when the requester created the approver's account")
    void refusedAfterCreation() throws Exception {
        String requester = administrator("maker");
        fourEyes(false);
        long approver = created(requester, "made-champion", Role.SECURITY_CHAMPION);

        long issue = pendingIssueRequestedBy("maker", requester, "CVE-INDEP-CREATED");
        approve(issue, signedIn(approver))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("approver-not-independent"))
                .andExpect(jsonPath("$.type").value("urn:vectispire:problem:approver-not-independent"))
                .andExpect(jsonPath("$.gesture").value("created"))
                .andExpect(jsonPath("$.windowDays").value(30));

        assertThat(issues.findById(issue).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.PENDING_APPROVAL.wireName());
    }

    @Test
    @DisplayName("is refused when the requester reset the approver's password")
    void refusedAfterPasswordReset() throws Exception {
        String requester = administrator("resetter");
        long approver = existing("reset-champion", Role.SECURITY_CHAMPION);
        fourEyes(false);
        changed(requester, approver, Map.of("password", PASSWORD));

        long issue = pendingIssueRequestedBy("resetter", requester, "CVE-INDEP-RESET");
        approve(issue, signedIn(approver))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("approver-not-independent"))
                .andExpect(jsonPath("$.gesture").value("password_reset"));
    }

    @Test
    @DisplayName("is refused when the requester gave the approver its role")
    void refusedAfterRoleChange() throws Exception {
        String requester = administrator("promoter");
        long approver = existing("promoted-champion", Role.USER);
        fourEyes(false);
        changed(requester, approver, Map.of("role", Role.CISO.name()));

        long issue = pendingIssueRequestedBy("promoter", requester, "CVE-INDEP-ROLE");
        approve(issue, signedIn(approver))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("approver-not-independent"))
                .andExpect(jsonPath("$.gesture").value("role_changed"));
    }

    @Test
    @DisplayName("is admitted when somebody else administered the approver")
    void admittedWhenSomebodyElseDidIt() throws Exception {
        String requester = administrator("bystander");
        String colleague = administrator("colleague");
        fourEyes(false);
        long approver = created(colleague, "colleague-champion", Role.SECURITY_CHAMPION);

        long issue = pendingIssueRequestedBy("bystander", requester, "CVE-INDEP-OTHER");
        approve(issue, signedIn(approver)).andExpect(status().isOk());

        assertThat(issues.findById(issue).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
    }

    @Test
    @DisplayName("is admitted when it is the approver who administered the requester: an approver settles directly anyway")
    void oneWayForTriage() throws Exception {
        String approverToken = administrator("staffing-admin");
        fourEyes(false);
        long requester = created(approverToken, "staffed-developer", Role.USER);

        long issue = pendingIssueRequestedBy("staffed-developer", signedIn(requester), "CVE-INDEP-ONEWAY");
        approve(issue, approverToken).andExpect(status().isOk());
    }

    @Test
    @DisplayName("is admitted once the window has passed")
    void admittedAfterTheWindow() throws Exception {
        String requester = administrator("old-maker");
        fourEyes(false);
        long approver = created(requester, "old-champion", Role.SECURITY_CHAMPION);
        // A day past the thirty: the gesture is history, not a second identity in the making.
        gestures.findAll().forEach(row -> {
            row.setOccurredAt(clock.instant().minus(Duration.ofDays(31)));
            gestures.save(row);
        });

        long issue = pendingIssueRequestedBy("old-maker", requester, "CVE-INDEP-OLD");
        approve(issue, signedIn(approver)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("follows the window the governor sets, and a window of zero switches the check off")
    void theWindowIsASetting() throws Exception {
        String requester = administrator("window-maker");
        fourEyes(false);
        long approver = created(requester, "window-champion", Role.SECURITY_CHAMPION);
        gestures.findAll().forEach(row -> {
            row.setOccurredAt(clock.instant().minus(Duration.ofDays(45)));
            gestures.save(row);
        });
        settings.set(Setting.FOUR_EYES_INDEPENDENCE_DAYS, "60");

        long refused = pendingIssueRequestedBy("window-maker", requester, "CVE-INDEP-WINDOW");
        approve(refused, signedIn(approver))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.windowDays").value(60));

        settings.set(Setting.FOUR_EYES_INDEPENDENCE_DAYS, "0");
        approve(refused, signedIn(approver)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("is not checked with four-eyes off: nothing changes")
    void nothingChangesWithFourEyesOff() throws Exception {
        String requester = administrator("lax-maker");
        fourEyes(false);
        long approver = created(requester, "lax-champion", Role.SECURITY_CHAMPION);

        long issue = pendingIssueRequestedBy("lax-maker", requester, "CVE-INDEP-OFF");
        fourEyes(false);
        approve(issue, signedIn(approver)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("is a window only the governor sets, bounded above")
    void theWindowIsTheGovernors() throws Exception {
        mvc.perform(authenticated(put("/api/v1/settings")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"four_eyes_independence_days\":\"0\"}"), asAdmin()))
                .andExpect(status().isForbidden());
        mvc.perform(authenticated(put("/api/v1/settings")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"four_eyes_independence_days\":\"3651\"}"),
                        tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false)))
                .andExpect(status().isBadRequest());
    }

    /**
     * A session for the approver, its password changed first: an account created or reset through the
     * API owes the change, and whoever holds the typed password makes it before acting.
     */
    private String signedIn(long account) {
        UserEntity user = users.findById(account).orElseThrow();
        user.setMustChangePassword(false);
        users.save(user);
        return sessionFor(account);
    }

    /** An administrator's session, under a name the history can be matched against. */
    private String administrator(String username) {
        return tokenFor(username, Role.ADMIN, false);
    }

    private long existing(String username, Role role) {
        tokenFor(username, role, false);
        return users.findByUsername(username).orElseThrow().getId();
    }

    private long created(String administrator, String username, Role role) throws Exception {
        mvc.perform(authenticated(post("/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("username", username, "password", PASSWORD, "role", role.name()))),
                        administrator))
                .andExpect(status().isOk());
        return users.findByUsername(username).orElseThrow().getId();
    }

    private void changed(String administrator, long account, Map<String, String> change) throws Exception {
        mvc.perform(authenticated(patch("/api/v1/users/" + account)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(change)), administrator))
                .andExpect(status().isOk());
    }

    /**
     * The requester, demoted to an account that cannot approve — the step an attacker takes some other
     * way — asks for an exemption under four-eyes, which queues it.
     */
    private long pendingIssueRequestedBy(String username, String token, String identifier) throws Exception {
        UserEntity requester = users.findByUsername(username).orElseThrow();
        requester.setRole(Role.USER.name());
        users.save(requester);
        fourEyes(true);

        long issue = issue(identifier);
        mvc.perform(authenticated(post("/api/v1/issues/" + issue + "/triage")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "status", "not_affected",
                                "justification", "vulnerable_code_not_in_execute_path",
                                "comment", "Please approve")))
                        , token))
                .andExpect(status().isOk());
        assertThat(issues.findById(issue).orElseThrow().getTriageStatus())
                .isEqualTo(TriageStatus.PENDING_APPROVAL.wireName());
        return issue;
    }

    private org.springframework.test.web.servlet.ResultActions approve(long issue, String token) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/issues/" + issue + "/triage")
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(Map.of(
                        "status", "not_affected",
                        "justification", "vulnerable_code_not_in_execute_path",
                        "comment", "Approved"))), token));
    }

    private void fourEyes(boolean on) {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, String.valueOf(on));
    }

    private long issue(String identifier) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + identifier.toLowerCase() + ".git");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
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
}
