package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.OutboxMessageEntity;
import com.asmolabs.vectispire.core.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.persistence.TeamEntity;
import com.asmolabs.vectispire.core.persistence.TeamTargetEntity;
import com.asmolabs.vectispire.core.persistence.TeamWebhookEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Outbox;
import com.asmolabs.vectispire.core.repositories.Projects;
import com.asmolabs.vectispire.core.repositories.Solutions;
import com.asmolabs.vectispire.core.repositories.TeamTargets;
import com.asmolabs.vectispire.core.repositories.TeamWebhooks;
import com.asmolabs.vectispire.core.repositories.Teams;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * A team granted a project is told about the project's repositories (decision 0023).
 *
 * <p>Visibility resolves a project grant into the repositories filed in the project; routing has
 * to read ownership the same way, or the team sees findings on screen its channel was never sent.
 */
@DisplayName("a project grant routes a team's notifications")
class ProjectNotificationRoutingTest extends VectispireContextTest {

    @Autowired
    private ScanDeltaNotifier notifier;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private Teams teams;

    @Autowired
    private TeamTargets teamTargets;

    @Autowired
    private TeamWebhooks teamWebhooks;

    @Autowired
    private Solutions solutions;

    @Autowired
    private Projects projects;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Outbox outbox;

    @Test
    @DisplayName("a scan of a repository filed in the team's project is queued for the team's channel")
    void aProjectGrantRoutesTheDelta() {
        long team = team("owners");
        long project = project();
        teamTargets.save(new TeamTargetEntity(team, "project", project));
        long filed = repository("https://example.invalid/routed.git");
        repositories.assignProject(filed, project);
        long unfiled = repository("https://example.invalid/elsewhere.git");

        enqueue(filed);
        enqueue(unfiled);

        assertThat(outbox.findAll().stream().map(OutboxMessageEntity::getTeamId).filter(java.util.Objects::nonNull))
                .as("one copy for the team, for the filed repository only")
                .containsExactly(team);
    }

    private void enqueue(long repositoryId) {
        ScanEntity scan = new ScanEntity();
        scan.setId(repositoryId * 1000);
        scan.setRepoId(repositoryId);
        IssueEntity issue = new IssueEntity();
        issue.setId(repositoryId * 1000);
        issue.setIdentifier("CVE-2021-44228");
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setSeverity(Severity.CRITICAL.wireName());
        issue.setState(IssueState.OPEN.wireName());
        transactions.executeWithoutResult(status -> notifier.enqueue(
                scan, new IssueSyncService.SyncResult(1, 0, 0, 0, List.of(issue), List.of())));
    }

    private long team(String name) {
        TeamEntity team = new TeamEntity();
        team.setName(name + "-" + System.nanoTime());
        team.setCreatedAt(Instant.now());
        long id = teams.save(team).getId();
        teamWebhooks.save(new TeamWebhookEntity(id, "https://hooks.example.invalid/" + id));
        return id;
    }

    private long project() {
        SolutionEntity solution = new SolutionEntity();
        solution.setName("solution-" + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        ProjectEntity project = new ProjectEntity();
        project.setSolutionId(solutions.save(solution).getId());
        project.setName("project");
        project.setCreatedAt(Instant.now());
        return projects.save(project).getId();
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }
}
