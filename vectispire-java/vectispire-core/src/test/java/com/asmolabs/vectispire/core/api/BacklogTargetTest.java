package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Which target a backlog row came from.
 *
 * <p>The backlog is global and an issue carried only its target's numeric id, so a hundred rows
 * said nothing about where each came from. Ordering by severity made that worse: consecutive
 * rows now jump between targets.
 */
@DisplayName("the target a backlog row names")
class BacklogTargetTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Containers containers;

    @Autowired
    private com.asmolabs.vectispire.core.repositories.Issues issues;

    @Autowired
    private com.asmolabs.vectispire.core.repositories.Scans scans;

    @Test
    @DisplayName("is named, for a repository and for an image alike")
    void bothKindsAreNamed() throws Exception {
        long repository = seedRepository("https://github.com/org/project.git");
        long container = seedContainer();
        seedIssue(repository, null, Severity.CRITICAL, false);
        seedIssue(null, container, Severity.HIGH, false);

        mvc.perform(authenticated(get("/api/v1/issues"), asAdmin()))
                .andExpect(status().isOk())
                // Severity order puts the repository's critical first.
                .andExpect(jsonPath("$.items[0].targetKind").value("repository"))
                // The short form, not the whole URL: this has to fit in a table column.
                .andExpect(jsonPath("$.items[0].targetName").value("org/project"))
                .andExpect(jsonPath("$.items[1].targetKind").value("container"))
                .andExpect(jsonPath("$.items[1].targetName").value("alpine:3.20"));
    }

    @Test
    @DisplayName("is added without moving anything the client already reads")
    void theExistingShapeIsUnchanged() throws Exception {
        long repository = seedRepository("https://github.com/org/project.git");
        seedIssue(repository, null, Severity.HIGH, false);

        // `@JsonUnwrapped` is the whole reason this assertion exists. Without it the entity
        // serializes under an `issue` key and *every* field the client reads moves at once —
        // the screen goes blank, and nothing in Java says so.
        mvc.perform(authenticated(get("/api/v1/issues"), asAdmin()))
                .andExpect(jsonPath("$.items[0].issue").doesNotExist())
                .andExpect(jsonPath("$.items[0].id").isNumber())
                .andExpect(jsonPath("$.items[0].severity").value("high"))
                .andExpect(jsonPath("$.items[0].triageStatus").value("under_review"))
                .andExpect(jsonPath("$.items[0].repoId").value((int) repository));
    }

    @Test
    @DisplayName("the is_kev filter the dashboard has always linked to now filters")
    void theKevLinkFilters() throws Exception {
        long repository = seedRepository("https://github.com/org/exploited.git");
        seedIssue(repository, null, Severity.HIGH, true);
        seedIssue(repository, null, Severity.CRITICAL, false);

        // The dashboard's "See the KEV catalogue" sent `is_kev=true` and nothing read it, so
        // the most actionable figure on that screen opened the entire backlog. Note the
        // critical is excluded: severity does not decide this filter, exploitation does.
        mvc.perform(authenticated(get("/api/v1/issues?is_kev=true"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.items[0].severity").value("high"))
                .andExpect(jsonPath("$.items[0].isKev").value(true));
    }

    @Test
    @DisplayName("the dashboard's recent scans name their target too, not just its id")
    void recentScansAreNamed() throws Exception {
        long container = seedContainer();
        com.asmolabs.vectispire.core.persistence.ScanEntity scan = new com.asmolabs.vectispire.core.persistence.ScanEntity();
        scan.setContainerId(container);
        scan.setBranch("-");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scans.save(scan);

        // The screen printed "Container 3", which names nothing an operator recognises and
        // cannot be matched against the target they came here about.
        mvc.perform(authenticated(get("/api/v1/dashboard"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recentScans[0].targetName").value("alpine:3.20"))
                .andExpect(jsonPath("$.recentScans[0].targetKind").value("container"));
    }

    @Test
    @DisplayName("a repository scan carries the branch it ran on, an image scan does not")
    void aRepositoryScanNamesItsBranch() throws Exception {
        long repository = seedRepository("https://github.com/org/project.git");
        com.asmolabs.vectispire.core.persistence.ScanEntity scan = new com.asmolabs.vectispire.core.persistence.ScanEntity();
        scan.setRepoId(repository);
        scan.setBranch("release/2.4");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scans.save(scan);

        // From the scan and not from the repository: a repository's branch can be changed
        // afterwards, and reading it from there would relabel a finished scan with a branch it
        // never ran on.
        mvc.perform(authenticated(get("/api/v1/dashboard"), asAdmin()))
                .andExpect(jsonPath("$.recentScans[0].targetName").value("org/project — release/2.4"));
    }

    private void seedIssue(Long repositoryId, Long containerId, Severity severity, boolean kev) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setContainerId(containerId);
        issue.setFingerprint("fp-" + severity + "-" + kev + "-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-" + severity.ordinal());
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setIsKev(kev);
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        issues.save(issue);
    }

    private long seedRepository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long seedContainer() {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("alpine");
        container.setTag("3.20");
        return containers.save(container).getId();
    }
}
