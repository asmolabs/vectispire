package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The backlog's exact identifier filter, on each engine.
 *
 * <p><b>The case rule is the engines' to disagree on.</b> MySQL's default collation compares without
 * case, PostgreSQL's {@code =} with it: a predicate comparing the column as stored passes the HTTP suite,
 * which runs on MySQL, and answers a lower-cased link with an empty list on PostgreSQL. Both sides are
 * lower-cased; this is where that is executed on the engine that would show its absence.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the backlog filtered by one identifier, on the engine")
class IssueIdentifierIntegrationTest {

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
    private IssueQueryService backlog;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private GitRepositoryRepository repositories;

    @Test
    @DisplayName("the identifier whatever the case asked and stored, never its neighbour")
    void exactlyAndCaseAside() {
        long repository = repository();
        issue(repository, "CVE-2021-4428");
        issue(repository, "CVE-2021-44228");
        issue(repository, "GHSA-jfh8-c2jp-5v3q");

        assertThat(identifiers(backlog.page(query("CVE-2021-4428"), Visibility.everything())))
                .containsExactly("CVE-2021-4428");
        assertThat(identifiers(backlog.page(query("cve-2021-4428"), Visibility.everything())))
                .as("a lower-cased link").containsExactly("CVE-2021-4428");
        assertThat(identifiers(backlog.page(query("GHSA-JFH8-C2JP-5V3Q"), Visibility.everything())))
                .as("an upper-cased link to a mixed-case identifier").containsExactly("GHSA-jfh8-c2jp-5v3q");
        assertThat(backlog.count(query("cve-2021-44228"), Visibility.everything())).isEqualTo(1);
    }

    private static IssueQueryService.BacklogQuery query(String identifier) {
        return new IssueQueryService.BacklogQuery(null, null, null, null, null, null, null, null,
                false, false, false, false, null, identifier, 500, 0,
                null, null, null, null, null, null, null, null);
    }

    private static List<String> identifiers(IssueQueryService.IssuePage page) {
        return page.items().stream().map(entry -> entry.issue().identifier()).toList();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/identifier-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void issue(long repository, String identifier) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repository);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier(identifier);
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
