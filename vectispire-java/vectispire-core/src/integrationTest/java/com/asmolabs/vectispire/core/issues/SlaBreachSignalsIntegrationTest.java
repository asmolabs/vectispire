package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
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
 * The SLA breach signal's query and mark, against a real engine.
 *
 * <p>The window is an instant range on {@code first_seen_at}, the settled statuses a {@code not in}
 * list, the page a {@code Limit} over an identifier keyset, and the mark a {@code ${ts}} column V64
 * added: each a place where an engine has answered differently before — a fractional second dropped
 * on one side of a comparison, an empty page read as the last. More issues than one page, so the
 * keyset is walked; the unit suite's {@code SiemBacklogSignalsTest} owns the rule's cases.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the SLA breach signal, on the engine")
class SlaBreachSignalsIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private SlaBreachSignals breaches;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private GitRepositoryRepository repositories;

    private long repoId;

    @BeforeEach
    void seed() {
        issues.deleteAll();
        repositories.deleteAll();
        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("breaches");
        repo.setUrl("ssh://git@example.com/team/breaches.git");
        repo.setBranch("main");
        repoId = repositories.save(repo).getId();
    }

    @Test
    @DisplayName("every crossing of the week is marked, over more than one page, and none twice")
    void marksEveryCrossingOnce() {
        Instant now = Instant.now();
        int crossings = SlaBreachSignals.BATCH + 7;
        for (int index = 0; index < crossings; index++) {
            // Critical, fifteen days: sixteen days ago crossed yesterday — with a fraction of a
            // second that a truncating engine would have to get right on both sides.
            issue("crossed-" + index, now.minus(Duration.ofDays(16)).minusMillis(index * 37L + 123),
                    TriageStatus.UNDER_REVIEW.wireName());
        }
        issue("long-late", now.minus(Duration.ofDays(30)), TriageStatus.UNDER_REVIEW.wireName());
        issue("settled", now.minus(Duration.ofDays(16)), TriageStatus.NOT_AFFECTED.wireName());

        assertThat(breaches.signalCrossings()).isEqualTo(crossings);
        assertThat(issues.findAll()).filteredOn(issue -> issue.getFingerprint().startsWith("crossed-"))
                .hasSize(crossings)
                .allSatisfy(issue -> assertThat(issue.getSlaBreachSignalledAt()).isNotNull());
        assertThat(issues.findAll()).filteredOn(issue -> !issue.getFingerprint().startsWith("crossed-"))
                .allSatisfy(issue -> assertThat(issue.getSlaBreachSignalledAt()).isNull());

        assertThat(breaches.signalCrossings()).isZero();
    }

    private void issue(String fingerprint, Instant firstSeen, String triage) {
        IssueEntity issue = new IssueEntity();
        issue.setFingerprint(fingerprint);
        issue.setIdentifier("CVE-2026-0001");
        issue.setType("vulnerability");
        issue.setSeverity("critical");
        issue.setState("open");
        issue.setTriageStatus(triage);
        issue.setRepoId(repoId);
        issue.setFirstSeenAt(firstSeen);
        issue.setLastSeenAt(Instant.now());
        issues.save(issue);
    }
}
