package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import jakarta.persistence.EntityManagerFactory;
import java.time.Instant;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * What a page costs when the estate grows.
 *
 * <p><b>Measured, not reasoned about.</b> Four routes answered by loading every issue in the
 * deployment as a managed entity — 23, 223 and 623 entity loads for 20, 220 and 620 issues, at a
 * constant query count, so one query returning everything and not an N+1. Each read two or three
 * fields off each row. The dashboard is the page every account lands on at sign-in, so the cost
 * was paid on every session, and at the sizes a real estate reaches it is the difference between a
 * page and a page nobody opens twice.
 *
 * <p><b>Why the fixture grows around the query rather than on it.</b> The assertion is not "this
 * route loads fewer than N entities" — a number like that is chosen to pass and says nothing. It
 * is "the count does not follow the size of the estate", which is the property that actually
 * broke, and it fails on a re-introduced {@code findAll} whatever constant somebody picks.
 *
 * <p>Two audits found seven such endpoints on {@code t_finding} and closed them; nobody counted
 * {@code t_issue} for another four days. This is the counter that would have said so.
 */
@DisplayName("what a page costs as the estate grows")
class ReadCostRoutesTest extends ApiTestBase {

    /** The counters are off in the shipped configuration, and are the whole instrument here. */
    @DynamicPropertySource
    static void statistics(DynamicPropertyRegistry registry) {
        registry.add("spring.jpa.properties.hibernate.generate_statistics", () -> "true");
    }

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Issues issues;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    /**
     * Room for the rows a page legitimately reads per target — scans, policies, the account — and
     * for a handful of issues where one is genuinely needed. Twenty issues fit under it; two
     * hundred do not, which is what makes the growth visible rather than the constant.
     */
    private static final int BOUNDED = 60;

    @Test
    @DisplayName("the backlog curve does not load the backlog")
    void trendsAreBounded() throws Exception {
        assertBoundedAsTheEstateGrows("/api/v1/dashboard/trends");
    }

    @Test
    @DisplayName("the compliance summary does not load every issue to average three columns")
    void complianceSummaryIsBounded() throws Exception {
        assertBoundedAsTheEstateGrows("/api/v1/compliance/summary");
    }

    @Test
    @DisplayName("the dashboard does not load the estate to draw a posture")
    void dashboardIsBounded() throws Exception {
        assertBoundedAsTheEstateGrows("/api/v1/dashboard");
    }

    @Test
    @DisplayName("the posture analytics does not load every issue to plot them")
    void postureAnalyticsIsBounded() throws Exception {
        assertBoundedAsTheEstateGrows("/api/v1/dashboard/posture-analytics");
    }

    private void assertBoundedAsTheEstateGrows(String route) throws Exception {
        long target = repository("https://example.invalid/cost-" + route.hashCode() + ".git");
        String admin = asAdmin();

        seed(target, 0, 20);
        long small = entitiesLoadedBy(route, admin);

        seed(target, 20, 220);
        long large = entitiesLoadedBy(route, admin);

        assertThat(large)
                .as("%s loaded %d entities for 220 issues against %d for 20 — the read follows the "
                        + "size of the estate, which is a whole-table read however few columns the "
                        + "answer needs. Project the columns instead of materialising the rows",
                        route, large, small)
                .isLessThanOrEqualTo(BOUNDED);
    }

    private long entitiesLoadedBy(String route, String token) throws Exception {
        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();
        int status = mvc.perform(authenticated(get(route), token)).andReturn().getResponse().getStatus();
        // A route that has been renamed answers 404 and loads nothing, which would pass the
        // assertion below forever. This is the guard against a measurement of nothing.
        assertThat(status).as("%s answered %d", route, status).isEqualTo(200);
        return statistics.getEntityLoadCount();
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void seed(long repoId, int from, int to) {
        for (int index = from; index < to; index++) {
            IssueEntity issue = new IssueEntity();
            issue.setRepoId(repoId);
            issue.setFingerprint("cost-" + repoId + "-" + index);
            issue.setType(FindingType.VULNERABILITY.wireName());
            issue.setIdentifier("CVE-COST-" + index);
            issue.setSeverity(Severity.HIGH.wireName());
            // Half resolved, so the resolved-only reads have something to average and the open
            // ones something to count: a fixture that is all one state hides half the queries.
            issue.setState(index % 4 == 0 ? IssueState.RESOLVED.wireName() : IssueState.OPEN.wireName());
            issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
            issue.setFirstSeenAt(Instant.now().minusSeconds(86_400L * 30));
            issue.setLastSeenAt(Instant.now());
            issue.setResolvedAt(index % 4 == 0 ? Instant.now().minusSeconds(86_400L * 5) : null);
            issue.setTimesSeen(1);
            issues.save(issue);
        }
    }
}
