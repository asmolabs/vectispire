package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The compliance summary's grouped projection, against a real engine.
 *
 * <p><b>Why this suite exists.</b> The summary used to ask nine count queries per target inside
 * its loop; they were collapsed into one {@code group by} over {@code (repoId, containerId,
 * severity, type, isKev)} plus one read of the SLA breaches. That query returns {@code Object[]}
 * rows the service casts — a {@code Long} id, a {@code String} severity, a boolean flag, a
 * {@code Number} count — and <b>a projection is exactly the kind of statement whose column types
 * differ by driver</b>. The storage differs: MySQL and MariaDB keep the flag as a {@code tinyint},
 * SQLite as a numeric affinity, PostgreSQL as a real boolean.
 *
 * <p><b>What this suite measured, against the expectation that wrote it.</b> Those differences do
 * not reach the service: the projection selects mapped entity attributes, so Hibernate normalises
 * every one of them, and replacing the tolerant conversion with a plain cast passes on all four.
 * The risk was real to reason about and turns out not to bite here — which is worth recording,
 * because the alternative is a defence nobody can evaluate.
 *
 * <p>The suite earns its place on the other half: that the {@code group by} <em>parses</em> on
 * each engine and that the counts it produces are attributed correctly. A statement that reads
 * fine and is wrong in SQL is what {@code HistoryQueriesIntegrationTest} was written for.
 *
 * <p>Until now the only coverage was the HTTP suite, which runs on SQLite, so a wrong cast would
 * have surfaced as a 500 on the compliance page of whichever engine the deployment actually
 * uses — in production, with every test green. That is the same shape as the defect
 * {@code HistoryQueriesIntegrationTest} was written for, and the reason it says depth is not the
 * point: what matters is that the statement reaches a server that parses it the way production
 * will.
 *
 * <p>The service is called rather than the repository, deliberately. The query parsing is half
 * the risk; the other half is the casting and the aggregation that read its rows, and only the
 * service exercises those.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the compliance summary's grouped counts")
class ComplianceSummaryIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    @BeforeAll
    static void start() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::start);
    }

    @AfterAll
    static void stop() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private ComplianceService compliance;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Containers containers;

    @Autowired
    private Issues issues;

    private long busy;
    private long quiet;
    private long image;

    @BeforeEach
    void seed() {
        issues.deleteAll();
        repositories.deleteAll();
        containers.deleteAll();

        busy = repository("ssh://git@example.com/team/busy.git", "Busy");
        quiet = repository("ssh://git@example.com/team/quiet.git", "Quiet");
        image = container("registry.example.com", "team/service", "1.4.0");

        // Spread across every axis the projection groups by, so one row lands in several tallies
        // at once — a severity, a type and the KEV flag are counted from the same group, and a
        // reader that took only the first would still pass a single-axis fixture.
        issue(busy, null, "fp-b1", Severity.CRITICAL, FindingType.VULNERABILITY, true, IssueState.OPEN);
        issue(busy, null, "fp-b2", Severity.HIGH, FindingType.VULNERABILITY, false, IssueState.OPEN);
        issue(busy, null, "fp-b3", Severity.HIGH, FindingType.SECRET, false, IssueState.OPEN);
        issue(busy, null, "fp-b4", Severity.LOW, FindingType.IAC, false, IssueState.OPEN);

        // Resolved, so it belongs to no tally: the query filters on state, and dropping that
        // filter is a plausible refactor that nothing else would catch.
        issue(busy, null, "fp-b5", Severity.CRITICAL, FindingType.VULNERABILITY, false, IssueState.RESOLVED);

        // A container target, because the projection groups by two nullable ids and the second
        // one is never exercised by a repository-only fixture.
        issue(null, image, "fp-i1", Severity.MEDIUM, FindingType.VULNERABILITY, false, IssueState.OPEN);
    }

    private long repository(String url, String name) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(name);
        entity.setBranch("main");
        return repositories.save(entity).getId();
    }

    private long container(String registry, String name, String tag) {
        ContainerEntity entity = new ContainerEntity();
        entity.setRegistry(registry);
        entity.setImageName(name);
        entity.setTag(tag);
        return containers.save(entity).getId();
    }

    private void issue(
            Long repoId,
            Long containerId,
            String fingerprint,
            Severity severity,
            FindingType type,
            boolean kev,
            IssueState state) {

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setContainerId(containerId);
        issue.setFingerprint(fingerprint);
        issue.setType(type.wireName());
        issue.setIdentifier(fingerprint.toUpperCase(java.util.Locale.ROOT));
        issue.setSeverity(severity.wireName());
        issue.setState(state.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setIsKev(kev);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private static ComplianceService.TargetCompliance targetOf(
            ComplianceService.ComplianceSummary summary, String targetId) {
        return summary.targets().stream()
                .filter(target -> targetId.equals(target.targetId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "no " + targetId + " among " + summary.targets().stream()
                                .map(ComplianceService.TargetCompliance::targetId)
                                .toList()));
    }

    @Test
    @DisplayName("the projection parses, its rows cast, and each target keeps its own count")
    void countsAreAttributedPerTarget() {
        ComplianceService.ComplianceSummary summary = compliance.getSummary(Visibility.everything());

        // Reaching this line at all is half the assertion: a projection the driver refuses, or a
        // column type the service cannot cast, fails before any number is compared.
        assertThat(summary.targets()).isNotEmpty();

        assertThat(targetOf(summary, "repo:" + busy).openIssuesCount())
                .as("four open issues on this repository, and not the resolved fifth")
                .isEqualTo(4);

        assertThat(targetOf(summary, "repo:" + quiet).openIssuesCount())
                .as("a target with no issue must not inherit another's group")
                .isZero();

        assertThat(targetOf(summary, "container:" + image).openIssuesCount())
                .as("the container id is the projection's second nullable key")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("the frameworks are still scored from those counts")
    void everyFrameworkIsEvaluated() {
        ComplianceService.ComplianceSummary summary = compliance.getSummary(Visibility.everything());

        // The counts feed the engine; if the grouping silently produced zeros the scores would
        // read as a clean estate rather than one with an open critical and a leaked secret.
        assertThat(summary.evaluations()).hasSize(6);
        assertThat(targetOf(summary, "repo:" + busy).overallScore())
                .as("a target with an open critical and a secret cannot score full marks")
                .isLessThan(100);
    }

    @Test
    @DisplayName("asking for one target reads the same numbers as the whole page")
    void theSingleTargetViewAgrees() {
        // Two code paths read the same grouped rows, and they used to be two sets of queries.
        // A divergence here would show as a per-target page that disagrees with the summary it
        // was opened from — the kind of defect a reader blames on caching.
        ComplianceService.ComplianceSummary all = compliance.getSummary(Visibility.everything());
        ComplianceService.ComplianceSummary one =
                compliance.getSummary("repo:" + busy, Visibility.everything());

        assertThat(targetOf(one, "repo:" + busy).openIssuesCount())
                .isEqualTo(targetOf(all, "repo:" + busy).openIssuesCount());
    }

    @Test
    @DisplayName("the SLA breach count is grouped per target too")
    void overdueCountsComeBackPerTarget() {
        ComplianceService.ComplianceSummary summary = compliance.getSummary(Visibility.everything());

        // Nothing here is overdue — the windows are the defaults and the issues were just
        // created — so the assertion is that the grouped read runs on this engine and attributes
        // nothing rather than everything. A query that failed to parse would not return zero.
        assertThat(List.of(
                        targetOf(summary, "repo:" + busy).overdueCount(),
                        targetOf(summary, "repo:" + quiet).overdueCount(),
                        targetOf(summary, "container:" + image).overdueCount()))
                .containsOnly(0L);
    }
}
