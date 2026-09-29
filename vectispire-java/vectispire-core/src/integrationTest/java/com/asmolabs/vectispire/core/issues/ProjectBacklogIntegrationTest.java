package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueSpecifications;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.LongStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The backlog narrowed to a project or a solution, on a real engine, past the sizes the data can reach.
 *
 * <p>A project's repositories are sized by the data, and the page and its count cannot be split into
 * statements the way a lookup is: the identifiers are written into the one statement as literals, in
 * lists of a thousand. The project here holds 1,500 repositories, so an issue on the first and one on
 * the last sit in different lists; the second case hands the predicate seventy thousand identifiers.
 * Bound as parameters, that statement failed here on PostgreSQL ("at most 65 535 parameters") — the
 * case that kills a return to {@code in(collection)}. <b>That limit is PostgreSQL's alone</b>: MySQL's
 * client-side statements and the SQLite driver accepted the bound statement, so a green run on those
 * two says nothing of the binding — they check the rest, a subquery for the solution, an {@code or} of
 * {@code in} lists and a statement text of several hundred kilobytes, each read by the engine.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the backlog of a project or a solution, on the engine")
class ProjectBacklogIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    private static final int FILED = 1_500;

    /** Seventy thousand identifiers no row carries — past the PostgreSQL driver's 65,535. */
    private static final List<Long> NOBODY = LongStream.rangeClosed(9_000_000, 9_070_000).boxed().toList();

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
    private IssueQueryService backlog;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ProjectRepository projects;

    @Autowired
    private SolutionRepository solutions;

    @Test
    @DisplayName("a project of 1,500 repositories: its issues, in every list of a thousand, and no others; a solution the same")
    void aLargeProject() {
        long solution = solution();
        long project = project(solution);
        List<Long> filed = new ArrayList<>();
        for (int i = 0; i < FILED; i++) {
            long repository = repository();
            repositories.assignProject(repository, project);
            filed.add(repository);
        }
        long first = filed.getFirst();
        long last = filed.getLast();
        issue(first, "CVE-FIRST");
        issue(last, "CVE-LAST");
        issue(repository(), "CVE-UNFILED");

        assertThat(identifiers(backlog.page(query(project, null), Visibility.everything())))
                .containsExactlyInAnyOrder("CVE-FIRST", "CVE-LAST");
        assertThat(identifiers(backlog.page(query(null, solution), Visibility.everything())))
                .as("the solution's repositories through a subquery on its projects")
                .containsExactlyInAnyOrder("CVE-FIRST", "CVE-LAST");
        assertThat(identifiers(backlog.page(query(project, null),
                        Visibility.only(List.of(new ScanTarget.Repository(last))))))
                .as("intersected with what the reader sees")
                .containsExactly("CVE-LAST");
    }

    @Test
    @DisplayName("seventy thousand repositories in the narrowing: the page and its count run on the engine")
    void pastTheBindLimit() {
        long repository = repository();
        issue(repository, "CVE-AMONG-MANY");
        IssueFilters filters = new IssueFilters(null, null, null, null, null, null, false, false, null,
                Visibility.everything()).within(Stream.concat(NOBODY.stream(), Stream.of(repository)).toList());

        assertThat(issues.findAll(IssueSpecifications.of(filters), PageRequest.of(0, 50)).getContent())
                .extracting(IssueEntity::getIdentifier)
                .containsExactly("CVE-AMONG-MANY");
        assertThat(issues.count(IssueSpecifications.of(filters))).isEqualTo(1);
    }

    private static IssueQueryService.BacklogQuery query(Long project, Long solution) {
        return new IssueQueryService.BacklogQuery(null, null, null, null, null, null, project, solution,
                false, false, false, false, null, 500, 0);
    }

    private static List<String> identifiers(IssueQueryService.IssuePage page) {
        return page.items().stream().map(entry -> entry.issue().identifier()).toList();
    }

    private long solution() {
        SolutionEntity solution = new SolutionEntity();
        solution.setName("large-" + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        return solutions.save(solution).getId();
    }

    private long project(long solution) {
        ProjectEntity project = new ProjectEntity();
        project.setSolutionId(solution);
        project.setName("large-" + System.nanoTime());
        project.setCreatedAt(Instant.now());
        return projects.save(project).getId();
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/large-" + System.nanoTime() + ".git");
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
