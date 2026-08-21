package com.asmolabs.zanshin.core.repositories;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.core.ZanshinApplication;
import com.asmolabs.zanshin.core.persistence.ComponentEntity;
import com.asmolabs.zanshin.core.persistence.Engine;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.persistence.TriageEventEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Limit;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The queries behind the history and inventory screens, against a real engine.
 *
 * <p><b>This suite exists because its absence shipped a broken page.</b> The history page's
 * decision count was written as {@code (:from is null or e.occurredAt >= :from)} — a nullable
 * parameter compared to a column. SQLite, which the HTTP suite runs on, accepts it. PostgreSQL
 * refuses it outright: <i>could not determine data type of parameter $2</i>, because an untyped
 * null in a comparison leaves the driver nothing to infer from. Every test was green and the
 * page returned 500 on the only engine anybody deploys.
 *
 * <p>The assertions here are deliberately shallow — a count, a list, a join. Depth is not the
 * point: <b>the point is that the statement reaches a server that parses it the way production
 * will</b>, and the queries these screens rely on are exactly the kind that read correct and are
 * wrong in SQL.
 */
@SpringBootTest(classes = ZanshinApplication.class)
@DisplayName("the history and inventory queries")
class HistoryQueriesIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();
    private static final Instant WHEN = Instant.parse("2026-03-03T08:00:00Z");

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
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Issues issues;

    @Autowired
    private TriageEvents events;

    @Autowired
    private Components components;

    private long repositoryId;
    private long scanId;
    private long issueId;

    @BeforeEach
    void seed() {
        events.deleteAll();
        components.deleteAll();
        issues.deleteAll();
        scans.deleteAll();
        repositories.deleteAll();

        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("ssh://git@example.com/art/arm-libs-spring.git");
        repository.setName("Arm Libs Spring");
        repository.setBranch("master");
        repositoryId = repositories.save(repository).getId();

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("master");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(WHEN);
        scan.setVersion("1.17.6");
        scan.setProjectType("maven");
        scanId = scans.save(scan).getId();

        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint("fp-CVE-2026-1234");
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-1234");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(WHEN);
        issue.setLastSeenAt(WHEN);
        issue.setLastSeenScanId(scanId);
        issue.setTimesSeen(1);
        issueId = issues.save(issue).getId();
    }

    @Test
    @DisplayName("counts a repository's decisions without a parameter the engine cannot type")
    void theDecisionCountRuns() {
        assertThatCode(() -> events.countForRepository(repositoryId)).doesNotThrowAnyException();
        assertThat(events.countForRepository(repositoryId)).isZero();

        events.save(decision());

        assertThat(events.countForRepository(repositoryId)).isEqualTo(1);
    }

    @Test
    @DisplayName("reads a page of issues' decisions in one statement")
    void decisionsForAPageOfIssues() {
        events.save(decision());

        List<TriageEventEntity> found = events.findForIssues(List.of(issueId));

        assertThat(found).hasSize(1);
        assertThat(found.getFirst().getFromStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
    }

    @Test
    @DisplayName("joins a component to the scan that saw it, and to the project version it shipped in")
    void theInventoryJoinRuns() {
        components.save(component("log4j-core", "2.14.1"));

        List<Object[]> rows = components.search("%log4j%", null, Limit.of(10));

        assertThat(rows).hasSize(1);
        assertThat(((ComponentEntity) rows.getFirst()[0]).getVersion()).isEqualTo("2.14.1");
        // The half of the answer that makes it actionable: our release, not the library's.
        assertThat(((ScanEntity) rows.getFirst()[1]).getVersion()).isEqualTo("1.17.6");
    }

    @Test
    @DisplayName("an absent version filter is a null the engine still has to type")
    void theOptionalVersionFilterRuns() {
        components.save(component("log4j-core", "2.14.1"));

        // `:version is null or c.version = :version` is the same shape that broke the decision
        // count. It survives here because the parameter is compared to a `varchar` column, which
        // gives the driver a type to infer — the difference is worth pinning rather than
        // remembering.
        assertThat(components.search("%log4j%", null, Limit.of(10))).hasSize(1);
        assertThat(components.search("%log4j%", "2.14.1", Limit.of(10))).hasSize(1);
        assertThat(components.search("%log4j%", "2.14.10", Limit.of(10))).isEmpty();
    }

    @Test
    @DisplayName("finds the scans whose SBOM nothing has indexed")
    void theBackfillSelectionRuns() {
        assertThat(scans.findWithSbomButNoComponents(Limit.of(10))).isEmpty();

        ScanEntity scan = scans.findById(scanId).orElseThrow();
        scan.setSbom("{\"artifacts\":[]}");
        scans.save(scan);

        assertThat(scans.findWithSbomButNoComponents(Limit.of(10)))
                .extracting(ScanEntity::getId)
                .containsExactly(scanId);

        components.save(component("anything", "1.0.0"));

        // Selected by the absence of rows, so indexing one takes it out of the queue with no
        // marker column that could disagree with the table it describes.
        assertThat(scans.findWithSbomButNoComponents(Limit.of(10))).isEmpty();
    }

    private TriageEventEntity decision() {
        TriageEventEntity event = new TriageEventEntity();
        event.setIssueId(issueId);
        event.setFromStatus(TriageStatus.UNDER_REVIEW.wireName());
        event.setToStatus(TriageStatus.NOT_AFFECTED.wireName());
        event.setActor("alice");
        event.setOrigin("manual");
        event.setOccurredAt(WHEN.plusSeconds(3600));
        event.setScanId(scanId);
        return event;
    }

    private ComponentEntity component(String name, String version) {
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scanId);
        component.setName(name);
        component.setVersion(version);
        component.setPurl("pkg:maven/org.apache.logging.log4j/" + name + "@" + version);
        component.setType("java-archive");
        component.setIsDirect(Boolean.TRUE);
        return component;
    }
}
