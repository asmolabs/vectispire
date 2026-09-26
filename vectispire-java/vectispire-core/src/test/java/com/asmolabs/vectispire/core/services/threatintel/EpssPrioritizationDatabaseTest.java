package com.asmolabs.vectispire.core.services.threatintel;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.EpssFleetSummary;
import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.EpssPrioritizedIssue;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelRecord;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * The fleet's exploitation ranking, against the database, with the threat feed replaced.
 *
 * <p>The routes pinned the cut of the ranking, the unknown EPSS and the visibility. What they did
 * not reach is what the service adds on top of the stored row: a KEV known only from the feed,
 * the feed's figures used when the scan carried none, the order of the ranking, and the name each
 * row is shown under.
 */
@DisplayName("ranking the fleet by exploitation")
class EpssPrioritizationDatabaseTest extends VectispireContextTest {

    @Autowired
    private EpssPrioritizationService epss;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Containers containers;

    @Autowired
    private Issues issues;

    @MockitoBean
    private ThreatIntelFeedService feed;

    private RepositoryEntity repository;

    private int fingerprints;

    @BeforeEach
    void aRepository() {
        repository = new RepositoryEntity();
        repository.setName("corp/payments");
        repository.setUrl("https://example.invalid/corp/payments.git");
        repository.setBranch("main");
        repository = repositories.save(repository);
        when(feed.lookupCves(any())).thenReturn(Map.of());
    }

    @Test
    @DisplayName("a CVE the scan did not flag but the feed lists as exploited counts as KEV")
    void theFeedCanMakeItKev() {
        issue(repository.getId(), null, "CVE-2026-1000", 7.5, null, "open");
        // Keyed in lower case, as the feed answers: the scanner and the feed disagree on case.
        when(feed.lookupCves(any())).thenReturn(Map.of(
                "cve-2026-1000", new ThreatIntelRecord("CVE-2026-1000", true, 0.42, 0.97, Instant.now(), null)));

        EpssFleetSummary summary = epss.getFleetSummary(Visibility.everything());

        assertThat(summary.activeKevCount()).isEqualTo(1);
        assertThat(summary.highEpssCount()).isEqualTo(1);
        EpssPrioritizedIssue row = summary.topPriorities().getFirst();
        assertThat(row.isKev()).isTrue();
        assertThat(row.epssScore()).isEqualTo(0.42);
        assertThat(row.epssPercentile()).isEqualTo(0.97);
    }

    @Test
    @DisplayName("the score the scan stored wins over the feed's")
    void theStoredScoreWins() {
        issue(repository.getId(), null, "CVE-2026-2000", 7.5, 0.05, "open");
        when(feed.lookupCves(any())).thenReturn(Map.of(
                "cve-2026-2000", new ThreatIntelRecord("CVE-2026-2000", false, 0.90, 0.99, Instant.now(), null)));

        assertThat(epss.getFleetSummary(Visibility.everything()).topPriorities().getFirst().epssScore())
                .isEqualTo(0.05);
    }

    @Test
    @DisplayName("the ranking is worst first, and a resolved issue is not in it")
    void rankedWorstFirst() {
        IssueEntity mild = issue(repository.getId(), null, "CVE-2026-3001", 3.1, 0.001, "open");
        IssueEntity armed = issue(repository.getId(), null, "CVE-2026-3002", 9.8, 0.60, "open");
        armed.setKev(true);
        issues.save(armed);
        IssueEntity middling = issue(repository.getId(), null, "CVE-2026-3003", 7.0, 0.10, "open");
        issue(repository.getId(), null, "CVE-2026-3004", 10.0, 0.99, "resolved");

        EpssFleetSummary summary = epss.getFleetSummary(Visibility.everything());

        assertThat(summary.totalVulnerabilities()).isEqualTo(3);
        assertThat(summary.topPriorities())
                .extracting(EpssPrioritizedIssue::issueId)
                .containsExactly(armed.getId(), middling.getId(), mild.getId());
    }

    @Test
    @DisplayName("a settled triage is not ranked; a dismissal awaiting approval, or a status nobody recognizes, still is")
    void settledTriageIsNotRanked() {
        IssueEntity dismissed = issue(repository.getId(), null, "CVE-2026-5001", 9.8, 0.9, "open");
        dismissed.setTriageStatus("not_affected");
        issues.save(dismissed);
        IssueEntity fixed = issue(repository.getId(), null, "CVE-2026-5002", 9.8, 0.9, "open");
        fixed.setTriageStatus("fixed");
        issues.save(fixed);
        IssueEntity requested = issue(repository.getId(), null, "CVE-2026-5003", 5.0, 0.1, "open");
        requested.setTriageStatus("pending_approval");
        issues.save(requested);
        IssueEntity unreadable = issue(repository.getId(), null, "CVE-2026-5004", 5.0, 0.1, "open");
        unreadable.setTriageStatus("untriaged");
        issues.save(unreadable);

        EpssFleetSummary summary = epss.getFleetSummary(Visibility.everything());

        assertThat(summary.totalVulnerabilities()).isEqualTo(2);
        assertThat(summary.topPriorities())
                .extracting(EpssPrioritizedIssue::issueId)
                .containsExactlyInAnyOrder(requested.getId(), unreadable.getId());
    }

    @Test
    @DisplayName("each row is named after its own target: repository by name, container by image and tag")
    void rowsAreNamed() {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("registry.example.invalid/shop");
        container.setTag("1.4.2");
        container = containers.save(container);
        issue(repository.getId(), null, "CVE-2026-4001", 9.0, 0.5, "open");
        issue(null, container.getId(), "CVE-2026-4002", 4.0, 0.01, "open");

        EpssFleetSummary summary = epss.getFleetSummary(Visibility.everything());

        assertThat(summary.topPriorities())
                .extracting(EpssPrioritizedIssue::targetName, EpssPrioritizedIssue::targetKind)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("corp/payments", "REPOSITORY"),
                        org.assertj.core.groups.Tuple.tuple("registry.example.invalid/shop:1.4.2", "CONTAINER"));
    }

    private IssueEntity issue(Long repoId, Long containerId, String cve, Double cvss, Double epssScore, String state) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repoId);
        issue.setContainerId(containerId);
        issue.setType("vulnerability");
        issue.setSource("grype");
        issue.setIdentifier(cve);
        issue.setSeverity("high");
        issue.setCvssScore(cvss);
        issue.setEpssScore(epssScore);
        issue.setState(state);
        issue.setFingerprint("fp-" + fingerprints++);
        issue.setTriageStatus("under_review");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        return issues.save(issue);
    }
}
