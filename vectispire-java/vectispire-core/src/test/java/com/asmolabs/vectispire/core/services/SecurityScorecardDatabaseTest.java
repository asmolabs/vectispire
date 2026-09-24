package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * How a target's grade is computed, against the database.
 *
 * <p>The routes checked that a clean repository scores 100 and that a KEV shows up in the counts;
 * the weights themselves — the numbers a badge in somebody's README is made of — and which issues
 * are allowed to weigh on it had no test. The licence inventory is replaced because it is read
 * from SBOM payloads, which would make each case here a scan fixture rather than a scorecard one.
 */
@DisplayName("computing a security scorecard")
class SecurityScorecardDatabaseTest extends VectispireContextTest {

    @Autowired
    private SecurityScorecardService scorecards;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Containers containers;

    @Autowired
    private Issues issues;

    @Autowired
    private Scans scans;

    @MockitoBean
    private LicenseGovernanceService licences;

    private RepositoryEntity repository;

    @BeforeEach
    void aRepository() {
        repository = new RepositoryEntity();
        repository.setName("corp/payments");
        repository.setUrl("https://example.invalid/corp/payments.git");
        repository.setBranch("main");
        repository = repositories.save(repository);
        when(licences.getInventory(any(), any())).thenReturn(List.of());
    }

    @Test
    @DisplayName("an unscanned target with no issues loses nothing but is told to produce evidence")
    void aCleanTarget() {
        SecurityScorecard card = scorecard();

        assertThat(card.score()).isEqualTo(100);
        assertThat(card.hasAttestation()).isFalse();
        assertThat(card.recommendations()).singleElement().asString().contains("attestation");
    }

    @Test
    @DisplayName("each weight applies as documented: KEV 25, reachable critical 15, other critical 8, high 4, licence 5, evidence +5")
    void theWeights() {
        completedScan();
        issue("critical", false, "REACHABLE", "open"); // -15
        issue("critical", false, "UNKNOWN", "open"); // -8
        issue("high", false, "UNKNOWN", "open"); // -4
        issue("medium", true, "UNKNOWN", "open"); // -25, and a KEV is counted whatever its severity
        when(licences.getInventory(repository.getId(), null)).thenReturn(List.of(
                licence(repository.getId(), "repository", false), licence(repository.getId(), "repository", true)));

        SecurityScorecard card = scorecard();

        // 100 - 15 - 8 - 4 - 25 - 5 + 5
        assertThat(card.score()).isEqualTo(48);
        assertThat(card.grade()).isEqualTo(SecurityGrade.D);
        assertThat(card.openCriticalCount()).isEqualTo(2);
        assertThat(card.openHighCount()).isEqualTo(1);
        assertThat(card.openKevCount()).isEqualTo(1);
        assertThat(card.licenseViolationCount()).isEqualTo(1);
        assertThat(card.hasAttestation()).isTrue();
    }

    @Test
    @DisplayName("a resolved issue weighs nothing")
    void resolvedIssuesAreFree() {
        completedScan();
        issue("critical", true, "REACHABLE", "resolved");

        assertThat(scorecard().score()).isEqualTo(100);
    }

    @Test
    @DisplayName("another target's issues and licences do not weigh on this one")
    void scopedToTheTarget() {
        RepositoryEntity other = new RepositoryEntity();
        other.setName("corp/other");
        other.setUrl("https://example.invalid/corp/other.git");
        other.setBranch("main");
        other = repositories.save(other);
        IssueEntity theirs = issue("critical", true, "REACHABLE", "open");
        theirs.setRepoId(other.getId());
        issues.save(theirs);
        // Returned by the inventory anyway: the service must not trust the filter it asked for.
        when(licences.getInventory(repository.getId(), null)).thenReturn(List.of(licence(other.getId(), "repository", false)));

        SecurityScorecard card = scorecard();

        assertThat(card.score()).isEqualTo(100);
        assertThat(card.openKevCount()).isZero();
        assertThat(card.licenseViolationCount()).isZero();
    }

    @Test
    @DisplayName("the score floors at zero rather than going negative")
    void theScoreFloors() {
        for (int i = 0; i < 5; i++) {
            issue("critical", true, "REACHABLE", "open");
        }

        SecurityScorecard card = scorecard();

        assertThat(card.score()).isZero();
        assertThat(card.grade()).isEqualTo(SecurityGrade.F);
    }

    @Test
    @DisplayName("a container is graded on its own issues and named by image and tag")
    void aContainer() {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("registry.example.invalid/shop");
        container.setTag("1.4.2");
        container = containers.save(container);
        IssueEntity high = issue("high", false, "UNKNOWN", "open");
        high.setRepoId(null);
        high.setContainerId(container.getId());
        issues.save(high);
        issue("critical", false, "UNKNOWN", "open"); // the repository's, not the container's

        SecurityScorecard card = scorecards.getContainerScorecard(container.getId()).orElseThrow();

        assertThat(card.targetName()).isEqualTo("registry.example.invalid/shop:1.4.2");
        assertThat(card.score()).isEqualTo(96);
        assertThat(card.openCriticalCount()).isZero();
    }

    @Test
    @DisplayName("an unknown target has no scorecard, rather than a perfect one")
    void unknownTarget() {
        assertThat(scorecards.getRepositoryScorecard(repository.getId() + 1000)).isEmpty();
        assertThat(scorecards.getContainerScorecard(424242L)).isEmpty();
    }

    private SecurityScorecard scorecard() {
        return scorecards.getRepositoryScorecard(repository.getId()).orElseThrow();
    }

    private void completedScan() {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repository.getId());
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scans.save(scan);
    }

    private int fingerprints;

    private IssueEntity issue(String severity, boolean kev, String reachability, String state) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repository.getId());
        issue.setType("vulnerability");
        issue.setSource("grype");
        issue.setSeverity(severity);
        issue.setState(state);
        issue.setFingerprint("fp-" + fingerprints++);
        issue.setKev(kev);
        issue.setReachability(reachability);
        issue.setTriageStatus("under_review");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        return issues.save(issue);
    }

    private static LicenseEntry licence(Long targetId, String kind, boolean compliant) {
        return new LicenseEntry("pkg", "1.0", null, compliant ? "MIT" : "AGPL-3.0", null, compliant,
                compliant ? null : "disallowed", targetId, kind, "corp/payments");
    }
}
