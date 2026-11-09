package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
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
    private GitRepositoryRepository repositories;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private SettingsService settings;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbc;

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
        scanned(target, "completed");

        // The scorecard's weights: three highs at four risk points each, 12 — 80, B. Counting the
        // settled two made it 20 points, 70.
        mvc.perform(authenticated(get("/api/v1/dashboard/posture-analytics?days=30"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targetScoreboard[0].openHigh").value(3))
                .andExpect(jsonPath("$.targetScoreboard[0].riskPoints").value(12.0))
                .andExpect(jsonPath("$.targetScoreboard[0].securityScore").value(80))
                .andExpect(jsonPath("$.targetScoreboard[0].maturityGrade").value("B"));
    }

    @Test
    @DisplayName("a target holding no completed scan ranks last as NO_DATA, with no score, never as the best")
    void aTargetNobodyScannedHasNoGrade() throws Exception {
        long scanned = repository("https://example.invalid/scanned.git");
        issue(scanned, "CVE-S-1", Duration.ofDays(3), null);
        scanned(scanned, "completed");
        // Its only findings came from somewhere else than a completed scan — an import, say — and
        // are all closed: the formula read 100, A, above a scanned target. A failed scan observes
        // nothing either.
        long unscanned = repository("https://example.invalid/unscanned.git");
        issue(unscanned, "CVE-U-1", Duration.ofDays(3), Duration.ofDays(1));
        scanned(unscanned, "failed");

        mvc.perform(authenticated(get("/api/v1/dashboard/posture-analytics?days=30"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targetScoreboard.length()").value(2))
                .andExpect(jsonPath("$.targetScoreboard[0].targetId").value(scanned))
                // One high, four risk points: the card's 93, A.
                .andExpect(jsonPath("$.targetScoreboard[0].securityScore").value(93))
                .andExpect(jsonPath("$.targetScoreboard[0].maturityGrade").value("A"))
                .andExpect(jsonPath("$.targetScoreboard[1].targetId").value(unscanned))
                .andExpect(jsonPath("$.targetScoreboard[1].maturityGrade").value("NO_DATA"))
                .andExpect(jsonPath("$.targetScoreboard[1].securityScore").value(nullValue()))
                .andExpect(jsonPath("$.targetScoreboard[1].riskPoints").value(nullValue()))
                // The counts stay, being true of what was read.
                .andExpect(jsonPath("$.targetScoreboard[1].totalResolved").value(1));
    }

    @Test
    @DisplayName("the ranking grades each target as its scorecard does, a clean scanned one at A+, the unscanned last")
    void theRankingIsTheScorecard() throws Exception {
        long clean = repository("https://example.invalid/clean.git");
        scanned(clean, "completed");
        long mixed = repository("https://example.invalid/mixed.git");
        issueOf(mixed, "CVE-M-1", Severity.CRITICAL, true);
        issueOf(mixed, "CVE-M-2", Severity.HIGH, false);
        issueOf(mixed, "CVE-M-3", Severity.MEDIUM, false);
        scanned(mixed, "completed");
        // Both read 0, F, on the ranking of old — a hundred less ten points a high — beside cards
        // that read 65 and 25 then: the heavy backlogs are where the two disagreed most. Under the
        // formula of decision 0036 they read 48 and 23, the second still lower than the first.
        long tenHighs = repository("https://example.invalid/ten-highs.git");
        long twentyHighs = repository("https://example.invalid/twenty-highs.git");
        for (int i = 0; i < 20; i++) {
            if (i < 10) {
                issueOf(tenHighs, "CVE-10-" + i, Severity.HIGH, false);
            }
            issueOf(twentyHighs, "CVE-20-" + i, Severity.HIGH, false);
        }
        scanned(tenHighs, "completed");
        scanned(twentyHighs, "completed");
        long unscanned = repository("https://example.invalid/imported-only.git");
        issueOf(unscanned, "CVE-I-1", Severity.CRITICAL, false);

        mvc.perform(authenticated(get("/api/v1/dashboard/posture-analytics?days=30"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targetScoreboard.length()").value(5))
                // A clean scanned target is ranked: it used to be left out, having no issue.
                .andExpect(jsonPath("$.targetScoreboard[0].targetId").value(clean))
                .andExpect(jsonPath("$.targetScoreboard[0].securityScore").value(100))
                .andExpect(jsonPath("$.targetScoreboard[0].maturityGrade").value("A_PLUS"))
                .andExpect(jsonPath("$.targetScoreboard[0].openHigh").value(0))
                // 25 (the exploited critical, in no severity) + 4 (high) + 0.5 (medium) = 29.5 risk
                // points, 58 by the formula, held at D's 54 by the exploited issue.
                .andExpect(jsonPath("$.targetScoreboard[1].targetId").value(mixed))
                .andExpect(jsonPath("$.targetScoreboard[1].securityScore").value(54))
                .andExpect(jsonPath("$.targetScoreboard[1].maturityGrade").value("D"))
                .andExpect(jsonPath("$.targetScoreboard[1].riskPoints").value(29.5))
                .andExpect(jsonPath("$.targetScoreboard[1].openMedium").value(1))
                .andExpect(jsonPath("$.targetScoreboard[2].targetId").value(tenHighs))
                .andExpect(jsonPath("$.targetScoreboard[2].securityScore").value(48))
                .andExpect(jsonPath("$.targetScoreboard[3].targetId").value(twentyHighs))
                .andExpect(jsonPath("$.targetScoreboard[3].securityScore").value(23))
                .andExpect(jsonPath("$.targetScoreboard[3].riskPoints").value(80.0))
                .andExpect(jsonPath("$.targetScoreboard[3].maturityGrade").value("F"))
                .andExpect(jsonPath("$.targetScoreboard[4].targetId").value(unscanned))
                .andExpect(jsonPath("$.targetScoreboard[4].maturityGrade").value("NO_DATA"))
                .andExpect(jsonPath("$.targetScoreboard[4].securityScore").value(nullValue()))
                .andExpect(jsonPath("$.targetScoreboard[4].openCritical").value(1));

        // **The claim itself: one target, one grade.** Each row against the card the repository
        // dialog and the public badge are drawn from, through its own route.
        JsonNode ranking = json.readTree(mvc.perform(
                        authenticated(get("/api/v1/dashboard/posture-analytics?days=30"), asAdmin()))
                .andReturn().getResponse().getContentAsString()).path("targetScoreboard");
        for (JsonNode row : ranking) {
            JsonNode card = json.readTree(mvc.perform(authenticated(
                            get("/api/v1/scorecards/repositories/" + row.path("targetId").asLong()), asAdmin()))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString());
            assertThat(row.path("securityScore")).as("score of %s", row.path("targetId")).isEqualTo(card.path("score"));
            assertThat(row.path("maturityGrade").asText()).isEqualTo(card.path("grade").asText());
            assertThat(row.path("riskPoints")).as("risk points of %s", row.path("targetId")).isEqualTo(card.path("riskPoints"));
            assertThat(row.path("openCritical").asLong()).isEqualTo(card.path("openCriticalCount").asLong());
            assertThat(row.path("openHigh").asLong()).isEqualTo(card.path("openHighCount").asLong());
        }
    }

    @Test
    @DisplayName("a clean scanned target the reader was not given is not ranked for them")
    void theRankingListsOnlyVisibleCleanTargets() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        try {
            long theirs = repository("https://example.invalid/someone-elses-clean.git");
            scanned(theirs, "completed");

            mvc.perform(authenticated(get("/api/v1/dashboard/posture-analytics?days=30"), asAdmin()))
                    .andExpect(jsonPath("$.targetScoreboard.length()").value(1));
            // Listing a clean target is disclosing it: the completed scans are the estate's, and
            // the ranking narrows them to the allowance before it grades any.
            mvc.perform(authenticated(get("/api/v1/dashboard/posture-analytics?days=30"), asReader()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.targetScoreboard.length()").value(0));
        } finally {
            settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());
        }
    }

    private void issueOf(long repoId, String identifier, Severity severity, boolean kev) {
        issue(repoId, identifier, Duration.ofDays(3), null);
        IssueEntity issue = issues.findAll().stream()
                .filter(i -> identifier.equals(i.getIdentifier()))
                .findFirst()
                .orElseThrow();
        issue.setSeverity(severity.wireName());
        issue.setKev(kev);
        issues.save(issue);
    }

    private void scanned(long repoId, String status) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus(status);
        scan.setCreatedAt(Instant.now());
        scans.save(scan);
    }

    /**
     * Two targets held at the same score — both at D's 54 by an exploited issue — rank by their risk
     * points, the fewer first (decision 0036), whichever was registered first. Inside F every score is
     * held at one, and without the points a team that fixed half its backlog would not move.
     */
    @Test
    @DisplayName("two targets of one score rank by their risk points, the fewer first")
    void tiesRankByRiskPoints() throws Exception {
        long heavier = repository("https://example.invalid/heavier.git");
        issueOf(heavier, "CVE-H-1", Severity.CRITICAL, true);
        issueOf(heavier, "CVE-H-2", Severity.HIGH, false);
        scanned(heavier, "completed");
        long lighter = repository("https://example.invalid/lighter.git");
        issueOf(lighter, "CVE-L-1", Severity.CRITICAL, true);
        scanned(lighter, "completed");

        mvc.perform(authenticated(get("/api/v1/dashboard/posture-analytics?days=30"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targetScoreboard[0].targetId").value(lighter))
                .andExpect(jsonPath("$.targetScoreboard[0].securityScore").value(54))
                .andExpect(jsonPath("$.targetScoreboard[0].riskPoints").value(25.0))
                .andExpect(jsonPath("$.targetScoreboard[1].targetId").value(heavier))
                .andExpect(jsonPath("$.targetScoreboard[1].securityScore").value(54))
                .andExpect(jsonPath("$.targetScoreboard[1].riskPoints").value(29.0));
    }

    /**
     * The day the grades changed formula on this installation, for the chart to mark: migration V69
     * writes it at the upgrade, where there were grades to change. The route hands it as stored, and
     * a value that is not a date draws no line rather than a wrong one.
     */
    @Test
    @DisplayName("the series carries the day the score formula changed here, and nothing when it did not")
    void theScoreFormulaChange() throws Exception {
        jdbc.update("delete from t_setting where " + keyColumn() + " = 'internal.scorecard_formula_changed_on'");
        mvc.perform(authenticated(get("/api/v1/dashboard/trends?days=30"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score_formula_changed_on").value(nullValue()));

        jdbc.update("insert into t_setting (" + keyColumn() + ", value) values ('internal.scorecard_formula_changed_on', '2026-10-20')");
        mvc.perform(authenticated(get("/api/v1/dashboard/trends?days=30"), asAdmin()))
                .andExpect(jsonPath("$.score_formula_changed_on").value("2026-10-20"));

        jdbc.update("update t_setting set value = 'soon' where " + keyColumn() + " = 'internal.scorecard_formula_changed_on'");
        mvc.perform(authenticated(get("/api/v1/dashboard/trends?days=30"), asAdmin()))
                .andExpect(jsonPath("$.score_formula_changed_on").value(nullValue()));
    }

    /** {@code key} is a reserved word on MySQL, and a plain identifier on PostgreSQL. */
    private String keyColumn() throws Exception {
        try (java.sql.Connection connection = jdbc.getDataSource().getConnection()) {
            return connection.getMetaData().getDatabaseProductName().toLowerCase(java.util.Locale.ROOT).contains("mysql")
                    ? "`key`"
                    : "\"key\"";
        }
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
