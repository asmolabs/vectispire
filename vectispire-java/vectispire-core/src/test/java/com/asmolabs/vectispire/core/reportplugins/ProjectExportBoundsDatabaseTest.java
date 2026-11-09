package com.asmolabs.vectispire.core.reportplugins;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportBounds;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * An export over its bounds is refused, never cut short (decision 0035 §1) — on the real database, under
 * bounds small enough to cross with two issues, since the standard ones would need 100,000 rows a run.
 */
@DisplayName("a project's export over its bounds")
class ProjectExportBoundsDatabaseTest extends VectispireContextTest {

    @Autowired
    private ProjectExportService exports;

    @Autowired
    private VisibilityService visibility;

    @Autowired
    private UserRepository users;

    @Autowired
    private SolutionRepository solutions;

    @Autowired
    private ProjectRepository projects;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private JdbcTemplate jdbc;

    private UserView requester;
    private long project;

    @BeforeEach
    void estate() {
        UserEntity user = new UserEntity();
        user.setUsername("bounds-" + System.nanoTime());
        user.setPassword("not-used");
        user.setRole(Role.USER.name());
        user.setIsActive(true);
        user.setMustChangePassword(false);
        user.setCreatedAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        requester = UserView.of(users.save(user));

        SolutionEntity solution = new SolutionEntity();
        solution.setName("solution-" + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        ProjectEntity entity = new ProjectEntity();
        entity.setSolutionId(solutions.save(solution).getId());
        entity.setName("ledger");
        entity.setCreatedAt(Instant.now());
        project = projects.save(entity).getId();

        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/ledger-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        long repositoryId = repositories.save(repository).getId();
        jdbc.update("update t_repository set project_id = ? where id = ?", project, repositoryId);

        issue(repositoryId);
        issue(repositoryId);
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        scan.setSbom("{}");
        scans.save(scan);
        for (String name : new String[] {"alpha", "beta"}) {
            ComponentEntity component = new ComponentEntity();
            component.setScanId(scan.getId());
            component.setRepoId(repositoryId);
            component.setScanCreatedAt(scan.getCreatedAt());
            component.setName(name);
            component.setVersion("1.0");
            component.setType("library");
            component.setIsDirect(true);
            components.save(component);
        }
    }

    @Test
    @DisplayName("the issues are counted before one is read, and two over a bound of one are refused")
    void tooManyIssues() {
        assertThatThrownBy(() -> export(new ProjectExportBounds(10_000_000, 1, 100)))
                .isInstanceOfSatisfying(ProjectExportTooLargeException.class, refused -> {
                    assertThat(refused.conflictCause()).contains("project-export-too-large");
                    assertThat(refused.members()).containsEntry("part", "issues").containsEntry("found", 2L)
                            .containsEntry("limit", 1L);
                    assertThat(refused.getMessage()).contains("would hold 2, above the 1");
                });
        assertThat(exported()).as("nothing left the platform, nothing was audited").isZero();
    }

    @Test
    @DisplayName("the components are bounded once merged")
    void tooManyComponents() {
        assertThatThrownBy(() -> export(new ProjectExportBounds(10_000_000, 100, 1)))
                .isInstanceOfSatisfying(ProjectExportTooLargeException.class, refused ->
                        assertThat(refused.members()).containsEntry("part", "inventory.components")
                                .containsEntry("found", 2L));
        assertThat(exported()).isZero();
    }

    @Test
    @DisplayName("the JSON stops at its bound rather than being written whole and measured")
    void tooLarge() {
        assertThatThrownBy(() -> export(new ProjectExportBounds(2_048, 100, 100)))
                .isInstanceOfSatisfying(ProjectExportTooLargeException.class, refused -> {
                    assertThat(refused.members()).containsEntry("part", "json_bytes").containsEntry("limit", 2_048L);
                    assertThat(refused.getMessage()).contains("passed 2048 bytes");
                });
        assertThat(exported()).isZero();
    }

    @Test
    @DisplayName("at its bounds exactly, the export is built and audited")
    void atTheBounds() {
        ProjectExportDownload download = export(new ProjectExportBounds(10_000_000, 2, 2));
        assertThat(download.content()).isNotEmpty();
        assertThat(exported()).isOne();
    }

    private ProjectExportDownload export(ProjectExportBounds bounds) {
        return exports.export(project, requester, visibility.allowance(requester, Visibility.everything()), null,
                new RequestActor(requester.username(), null, null), bounds);
    }

    private long exported() {
        return auditLog.findAll().stream().filter(entry -> "PROJECT_EXPORTED".equals(entry.getOperationType())).count();
    }

    private void issue(long repositoryId) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint("fp-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2024-" + System.nanoTime() % 100_000);
        issue.setSeverity(Severity.MEDIUM.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus("under_review");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }
}
