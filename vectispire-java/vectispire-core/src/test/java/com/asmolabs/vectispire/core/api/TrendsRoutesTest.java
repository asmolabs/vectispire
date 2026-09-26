package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The backlog over time, over HTTP.
 *
 * <p>{@code BacklogTrendTest} proves the day arithmetic. What only a running application shows is
 * the part this codebase has already got wrong once: that a series is <b>narrowed by
 * visibility</b>. The aggregate that leaked here was precisely the one returning numbers rather
 * than rows — a chart feels less like somebody's data than a list does, and that is the whole
 * reason it needs its own assertion.
 */
@DisplayName("the backlog over time, over HTTP")
class TrendsRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("the window is a day per point, and the series counts what is open")
    void drawsTheWindow() throws Exception {
        long target = repository("https://example.invalid/trend.git");
        issue(target, "CVE-OPEN", Duration.ofDays(5), null);

        mvc.perform(authenticated(get("/api/v1/dashboard/trends?days=7"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.points.length()").value(7))
                // Still open today, so it stands on the last point.
                .andExpect(jsonPath("$.points[6].open").value(1))
                // Nothing resolved: the mean is absent rather than zero, because zero would read
                // as "fixed the day it appeared".
                .andExpect(jsonPath("$.mean_days_to_resolve").doesNotExist())
                .andExpect(jsonPath("$.resolved_in_window").value(0));
    }

    @Test
    @DisplayName("an issue resolved in the window leaves the backlog and shows up in the mean")
    void countsResolution() throws Exception {
        long target = repository("https://example.invalid/resolved.git");
        // Seen 6 days ago, resolved 4 days ago: two days to fix.
        issue(target, "CVE-FIXED", Duration.ofDays(6), Duration.ofDays(4));

        mvc.perform(authenticated(get("/api/v1/dashboard/trends?days=7"), asAdmin()))
                .andExpect(jsonPath("$.points[6].open").value(0))
                .andExpect(jsonPath("$.resolved_in_window").value(1))
                .andExpect(jsonPath("$.mean_days_to_resolve").exists());
    }

    @Test
    @DisplayName("a reader assigned to nothing gets an empty series, not the deployment's history")
    void theSeriesIsNarrowedByVisibility() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        try {
            long target = repository("https://example.invalid/not-yours.git");
            issue(target, "CVE-PRIVATE", Duration.ofDays(3), null);

            // An administrator sees it — somebody has to.
            mvc.perform(authenticated(get("/api/v1/dashboard/trends?days=7"), asAdmin()))
                    .andExpect(jsonPath("$.points[6].open").value(1));

            // **The assertion this class exists for.** "How much is there that I am not shown" is
            // information too, and a curve discloses it just as plainly as a list would.
            mvc.perform(authenticated(get("/api/v1/dashboard/trends?days=7"), asReader()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.points[6].open").value(0))
                    .andExpect(jsonPath("$.resolved_in_window").value(0));
        } finally {
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());
        }
    }

    @Test
    @DisplayName("an absurd window is clamped rather than failing the request")
    void clampsTheWindow() throws Exception {
        // A chart is not a place to answer 400 over a query string, and the ceiling exists because
        // the window is also the number of days iterated.
        mvc.perform(authenticated(get("/api/v1/dashboard/trends?days=100000"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.points.length()").value(365));

        mvc.perform(authenticated(get("/api/v1/dashboard/trends?days=0"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.points.length()").value(1));
    }

    @Test
    @DisplayName("GET /api/v1/dashboard/posture-analytics returns full MTTR by severity and target scoreboard")
    void returnsPostureAnalytics() throws Exception {
        long target = repository("https://example.invalid/analytics.git");
        issue(target, "CVE-ANALYTICS-1", Duration.ofDays(10), Duration.ofDays(2));

        mvc.perform(authenticated(get("/api/v1/dashboard/posture-analytics?days=30"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.windowDays").value(30))
                .andExpect(jsonPath("$.totalResolvedInWindow").value(1))
                .andExpect(jsonPath("$.targetScoreboard").isArray());
    }

    @Test
    @DisplayName("the maturity ranking leaves settled triage out, and keeps what is only requested or unreadable")
    void theRankingIgnoresSettledTriage() throws Exception {
        long target = repository("https://example.invalid/triaged.git");
        triaged(target, "CVE-T-1", TriageStatus.NOT_AFFECTED.wireName());
        triaged(target, "CVE-T-2", TriageStatus.FIXED.wireName());
        triaged(target, "CVE-T-3", TriageStatus.PENDING_APPROVAL.wireName());
        triaged(target, "CVE-T-4", TriageStatus.UNDER_REVIEW.wireName());
        // Written by nobody this version knows: still nobody's decision, so still counted.
        triaged(target, "CVE-T-5", "untriaged");

        // Three highs at ten points each: 70, grade C. Counting the settled two made it 50.
        mvc.perform(authenticated(get("/api/v1/dashboard/posture-analytics?days=30"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targetScoreboard[0].openHigh").value(3))
                .andExpect(jsonPath("$.targetScoreboard[0].securityScore").value(70))
                .andExpect(jsonPath("$.targetScoreboard[0].maturityGrade").value("C"));
    }

    private void triaged(long repoId, String identifier, String triageStatus) {
        issue(repoId, identifier, Duration.ofDays(3), null);
        IssueEntity issue = issues.findAll().stream()
                .filter(i -> identifier.equals(i.getIdentifier()))
                .findFirst()
                .orElseThrow();
        issue.setTriageStatus(triageStatus);
        issues.save(issue);
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void issue(long repoId, String identifier, Duration age, Duration resolvedAgo) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setFingerprint(identifier + "-" + repoId);
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(resolvedAgo == null ? IssueState.OPEN.wireName() : IssueState.RESOLVED.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now().minus(age));
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        if (resolvedAgo != null) {
            issue.resolveAt(Instant.now().minus(resolvedAgo));
        }
        issues.save(issue);
    }
}
