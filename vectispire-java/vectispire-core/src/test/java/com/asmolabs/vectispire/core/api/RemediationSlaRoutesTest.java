package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.SettingsService;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The remediation deadline, over HTTP.
 *
 * <p>{@code RemediationSlaTest} proves the calculation. What only a running application can show
 * is the pair of things a screen depends on: that the figure on the dashboard and the list the
 * figure links to <b>count the same rows</b>, and that a deadline reaches the client at all —
 * computed on the server, because a client re-deriving it from the policy would be a second
 * implementation of lateness.
 */
@DisplayName("the remediation deadline, over HTTP")
class RemediationSlaRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("an issue past its window arrives marked overdue, with its deadline")
    void anOverdueIssueSaysSo() throws Exception {
        long target = repository("https://example.invalid/late.git");
        // A critical first seen 20 days ago, against the default 15-day window.
        issue(target, "CVE-LATE", Severity.CRITICAL, Duration.ofDays(20), TriageStatus.UNDER_REVIEW);

        mvc.perform(authenticated(get("/api/v1/issues?search=CVE-LATE"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items[0].slaState").value("overdue"))
                .andExpect(jsonPath("$.items[0].slaDueAt").exists())
                // Negative: one signed field, read from the late side.
                .andExpect(jsonPath("$.items[0].slaDays").value(-5));
    }

    @Test
    @DisplayName("a fresh one is on time, and a severity with no window carries no deadline")
    void theOtherTwoAnswers() throws Exception {
        long target = repository("https://example.invalid/fresh.git");
        issue(target, "CVE-FRESH", Severity.CRITICAL, Duration.ofDays(1), TriageStatus.UNDER_REVIEW);
        issue(target, "CVE-NOIDEA", Severity.UNKNOWN, Duration.ofDays(400), TriageStatus.UNDER_REVIEW);

        mvc.perform(authenticated(get("/api/v1/issues?search=CVE-FRESH"), asAdmin()))
                .andExpect(jsonPath("$.items[0].slaState").value("on_time"));

        // 400 days old and no deadline at all: "unknown" is what a scanner says when it cannot
        // tell, and a deadline on it would fill the report with lateness that means nothing.
        mvc.perform(authenticated(get("/api/v1/issues?search=CVE-NOIDEA"), asAdmin()))
                .andExpect(jsonPath("$.items[0].slaState").doesNotExist())
                .andExpect(jsonPath("$.items[0].slaDueAt").doesNotExist());
    }

    @Test
    @DisplayName("the dashboard figure and the list it links to count the same rows")
    void theFigureAndTheListAgree() throws Exception {
        long target = repository("https://example.invalid/mixed.git");
        issue(target, "CVE-A", Severity.CRITICAL, Duration.ofDays(30), TriageStatus.UNDER_REVIEW);
        issue(target, "CVE-B", Severity.HIGH, Duration.ofDays(45), TriageStatus.AFFECTED);
        issue(target, "CVE-C", Severity.MEDIUM, Duration.ofDays(30), TriageStatus.UNDER_REVIEW);
        // Settled, and older than any window: a triage decision is not lateness.
        issue(target, "CVE-D", Severity.CRITICAL, Duration.ofDays(300), TriageStatus.NOT_AFFECTED);

        // Two late — the critical at 30 days and the high at 45 — and neither the medium, which
        // has 90, nor the dismissed one.
        mvc.perform(authenticated(get("/api/v1/dashboard"), asAdmin()))
                .andExpect(jsonPath("$.posture.overdueCount").value(2));

        // The same clause behind both, which is the point: a count and a list built from two
        // copies of one filter disagree the first time either is edited.
        mvc.perform(authenticated(get("/api/v1/issues?overdue=true"), asAdmin()))
                .andExpect(jsonPath("$.total").value(2));
    }

    @Test
    @DisplayName("a window set to zero disables that severity rather than breaching it")
    void zeroDisables() throws Exception {
        long target = repository("https://example.invalid/zeroed.git");
        issue(target, "CVE-ZEROED", Severity.CRITICAL, Duration.ofDays(300), TriageStatus.UNDER_REVIEW);

        settings.set(Setting.SLA_CRITICAL_DAYS, "0");

        // The opposite reading — zero as "due immediately" — would put a whole backlog into
        // breach from a gesture that looked like switching something off.
        mvc.perform(authenticated(get("/api/v1/issues?search=CVE-ZEROED"), asAdmin()))
                .andExpect(jsonPath("$.items[0].slaState").doesNotExist());
        mvc.perform(authenticated(get("/api/v1/dashboard"), asAdmin()))
                .andExpect(jsonPath("$.posture.overdueCount").value(0));

        settings.set(Setting.SLA_CRITICAL_DAYS, "15");
    }

    @Test
    @DisplayName("the windows are settings, and changing one changes the verdict")
    void thePolicyIsConfigured() throws Exception {
        long target = repository("https://example.invalid/tightened.git");
        issue(target, "CVE-TIGHT", Severity.MEDIUM, Duration.ofDays(20), TriageStatus.UNDER_REVIEW);

        mvc.perform(authenticated(get("/api/v1/issues?search=CVE-TIGHT"), asAdmin()))
                .andExpect(jsonPath("$.items[0].slaState").value("on_time"));

        // Read per request rather than cached: an operator who tightens a window and sees no
        // change on the next page concludes the setting does nothing.
        settings.set(Setting.SLA_MEDIUM_DAYS, "10");
        mvc.perform(authenticated(get("/api/v1/issues?search=CVE-TIGHT"), asAdmin()))
                .andExpect(jsonPath("$.items[0].slaState").value("overdue"));

        settings.set(Setting.SLA_MEDIUM_DAYS, "90");
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void issue(long repoId, String identifier, Severity severity, Duration age, TriageStatus triage) {
        Instant firstSeen = Instant.now().minus(age);
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(triage.wireName());
        issue.setFirstSeenAt(firstSeen);
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
