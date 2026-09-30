package com.asmolabs.vectispire.core.posture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.inventory.LicenseGovernanceService;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
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
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private JdbcTemplate jdbc;

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
        when(licences.getInventory(any(VisibleTarget.class))).thenReturn(List.of());
    }

    @Test
    @DisplayName("a target never scanned has no grade and no score, rather than a perfect one, and is told to complete a scan")
    void anUnscannedTarget() {
        SecurityScorecard card = scorecard();

        // It read 100/100, A+ — on the card, and on the public badge of a repository registered and
        // never scanned: the formula subtracts what it finds from a hundred, and nobody had looked.
        assertThat(card.grade()).isEqualTo(SecurityGrade.NO_DATA);
        assertThat(card.score()).isNull();
        assertThat(card.totalTargets()).isEqualTo(1);
        assertThat(card.observedTargets()).isZero();
        assertThat(card.hasAttestation()).isFalse();
        // The attestation is issued from a completed scan, so completing one is the advice —
        // not "generate attestations", a step this product does not have.
        assertThat(card.recommendations()).singleElement().asString().startsWith("Complete a scan");
    }

    @Test
    @DisplayName("a target scanned clean scores a hundred, A+, observed")
    void aScannedCleanTarget() {
        completedScan();

        SecurityScorecard card = scorecard();

        assertThat(card.score()).isEqualTo(100);
        assertThat(card.grade()).isEqualTo(SecurityGrade.A_PLUS);
        assertThat(card.observedTargets()).isEqualTo(1);
        assertThat(card.recommendations()).singleElement().asString().startsWith("Maintain current posture");
    }

    @Test
    @DisplayName("a scan in flight or failed does not observe a target; a completed one before it still does")
    void onlyACompletedScanObserves() {
        scan(repository.getId(), null, "scanning");
        scan(repository.getId(), null, "failed");
        assertThat(scorecard().grade()).isEqualTo(SecurityGrade.NO_DATA);

        completedScan();
        scan(repository.getId(), null, "scanning");
        assertThat(scorecard().grade()).isEqualTo(SecurityGrade.A_PLUS);
    }

    @Test
    @DisplayName("a scope none of whose targets was scanned has no grade, however scanned the rest of the estate")
    void anUnscannedScope() {
        RepositoryEntity scanned = anotherRepository("corp/scanned");
        scan(scanned.getId(), null, "completed");

        SecurityScorecard card = scorecards.getScopeScorecard(scopeOf(new ScanTarget.Repository(repository.getId())));

        assertThat(card.grade()).isEqualTo(SecurityGrade.NO_DATA);
        assertThat(card.score()).isNull();
        assertThat(card.targetKind()).isEqualTo("project");
        assertThat(card.totalTargets()).isEqualTo(1);
        assertThat(card.observedTargets()).isZero();
    }

    @Test
    @DisplayName("a scope scanned in part is capped at its observed share and told which remain; scanned whole, it is not")
    void aPartlyScannedScope() {
        RepositoryEntity second = anotherRepository("corp/second");
        RepositoryEntity third = anotherRepository("corp/third");
        RepositoryEntity fourth = anotherRepository("corp/fourth");
        completedScan();
        VisibleScope scope = scopeOf(
                new ScanTarget.Repository(repository.getId()), new ScanTarget.Repository(second.getId()),
                new ScanTarget.Repository(third.getId()), new ScanTarget.Repository(fourth.getId()));

        SecurityScorecard partly = scorecards.getScopeScorecard(scope);

        // A hundred on the one scanned, clean; three nobody looked at weighed as clean too, A+.
        assertThat(partly.score()).isEqualTo(25);
        assertThat(partly.grade()).isEqualTo(SecurityGrade.F);
        assertThat(partly.totalTargets()).isEqualTo(4);
        assertThat(partly.observedTargets()).isEqualTo(1);
        assertThat(partly.recommendations()).first().asString()
                .startsWith("Scan the 3 target(s) never scanned: the score covers 1/4 target(s)");

        scan(second.getId(), null, "completed");
        scan(third.getId(), null, "completed");
        scan(fourth.getId(), null, "completed");
        SecurityScorecard whole = scorecards.getScopeScorecard(scope);

        assertThat(whole.score()).isEqualTo(100);
        assertThat(whole.grade()).isEqualTo(SecurityGrade.A_PLUS);
        assertThat(whole.observedTargets()).isEqualTo(4);
        assertThat(whole.recommendations()).noneSatisfy(line -> assertThat(line).startsWith("Scan the"));
    }

    @Test
    @DisplayName("the portfolio counts the targets the caller sees, and is capped by the ones never scanned")
    void thePortfolio() {
        RepositoryEntity unscanned = anotherRepository("corp/unscanned");
        completedScan();
        Visibility both = Visibility.only(List.of(
                new ScanTarget.Repository(repository.getId()), new ScanTarget.Repository(unscanned.getId())));

        SecurityScorecard card = scorecards.getGlobalScorecard(both);

        assertThat(card.totalTargets()).isEqualTo(2);
        assertThat(card.observedTargets()).isEqualTo(1);
        assertThat(card.score()).isEqualTo(50);
        assertThat(scorecards.getGlobalScorecard(Visibility.only(List.of(new ScanTarget.Repository(unscanned.getId()))))
                .grade()).isEqualTo(SecurityGrade.NO_DATA);
    }

    @Test
    @DisplayName("issues past their remediation deadline are counted and advised on, for this target only, without moving the score")
    void overdueIssues() {
        completedScan();
        Instant longAgo = Instant.now().minus(Duration.ofDays(40));
        // Past the 30-day high window, and past the 15-day critical one.
        aged(issue("high", false, "open"), longAgo);
        aged(issue("critical", false, "open"), longAgo);
        // Inside its window.
        issue("high", false, "open");
        // Old, but settled by a triage decision: that is not lateness.
        IssueEntity settled = aged(issue("critical", false, "open"), longAgo);
        settled.setTriageStatus("not_affected");
        issues.save(settled);
        // Old and late, but another target's.
        RepositoryEntity other = new RepositoryEntity();
        other.setName("corp/other");
        other.setUrl("https://example.invalid/corp/other.git");
        other.setBranch("main");
        other = repositories.save(other);
        IssueEntity theirs = aged(issue("critical", false, "open"), longAgo);
        theirs.setRepoId(other.getId());
        issues.save(theirs);

        SecurityScorecard card = scorecard();

        assertThat(card.overdueCount()).isEqualTo(2);
        assertThat(card.recommendations()).anySatisfy(line -> assertThat(line).startsWith("Resolve 2 issue(s) past"));
        // 100 - 8 (the unsettled critical) - 4 - 4 (two highs) + 5: lateness is not scored.
        assertThat(card.score()).isEqualTo(89);
        assertThat(scorecards.getGlobalScorecard(Visibility.everything()).overdueCount()).isEqualTo(3);
    }

    @Test
    @DisplayName("each weight applies as documented: KEV 25, critical 8, high 4, licence 5, evidence +5")
    void theWeights() {
        completedScan();
        // Marked reachable in the dormant column, as a hand edit or a future import would: it
        // cost 15 instead of 8 while the scorecard read the column, on a claim nothing established.
        markedReachable(issue("critical", false, "open")); // -8
        issue("critical", false, "open"); // -8
        issue("high", false, "open"); // -4
        issue("medium", true, "open"); // -25, and a KEV is counted whatever its severity
        when(licences.getInventory(checked(new ScanTarget.Repository(repository.getId())))).thenReturn(List.of(
                licence(repository.getId(), "repository", false), licence(repository.getId(), "repository", true)));

        SecurityScorecard card = scorecard();

        // 100 - 8 - 8 - 4 - 25 - 5 + 5
        assertThat(card.score()).isEqualTo(55);
        assertThat(card.grade()).isEqualTo(SecurityGrade.C);
        assertThat(card.openCriticalCount()).isEqualTo(2);
        assertThat(card.openHighCount()).isEqualTo(1);
        assertThat(card.openKevCount()).isEqualTo(1);
        assertThat(card.licenseViolationCount()).isEqualTo(1);
        assertThat(card.hasAttestation()).isTrue();
    }

    @Test
    @DisplayName("a settled triage weighs nothing; a dismissal awaiting approval, or a status nobody recognizes, still does")
    void settledTriageIsFree() {
        completedScan();
        triaged(issue("critical", true, "open"), "not_affected");
        triaged(issue("critical", false, "open"), "fixed");
        triaged(issue("high", false, "open"), "pending_approval");
        triaged(issue("high", false, "open"), "affected");
        // A status this version does not know is nobody's decision, so it still counts.
        triaged(issue("critical", false, "open"), "untriaged");

        SecurityScorecard card = scorecard();

        // 100 - 4 - 4 - 8 + 5: the two settled criticals and the KEV among them are gone from the
        // score and from the counts alike; the unreadable one is not.
        assertThat(card.score()).isEqualTo(89);
        assertThat(card.openCriticalCount()).isEqualTo(1);
        assertThat(card.openKevCount()).isZero();
        assertThat(card.openHighCount()).isEqualTo(2);
    }

    @Test
    @DisplayName("a resolved issue weighs nothing")
    void resolvedIssuesAreFree() {
        completedScan();
        issue("critical", true, "resolved");

        assertThat(scorecard().score()).isEqualTo(100);
    }

    @Test
    @DisplayName("another target's issues and licences do not weigh on this one")
    void scopedToTheTarget() {
        completedScan();
        RepositoryEntity other = new RepositoryEntity();
        other.setName("corp/other");
        other.setUrl("https://example.invalid/corp/other.git");
        other.setBranch("main");
        other = repositories.save(other);
        IssueEntity theirs = issue("critical", true, "open");
        theirs.setRepoId(other.getId());
        issues.save(theirs);
        // Returned by the inventory anyway: the service must not trust the filter it asked for.
        when(licences.getInventory(checked(new ScanTarget.Repository(repository.getId())))).thenReturn(List.of(licence(other.getId(), "repository", false)));

        SecurityScorecard card = scorecard();

        assertThat(card.score()).isEqualTo(100);
        assertThat(card.openKevCount()).isZero();
        assertThat(card.licenseViolationCount()).isZero();
    }

    @Test
    @DisplayName("the score floors at zero rather than going negative")
    void theScoreFloors() {
        completedScan();
        for (int i = 0; i < 5; i++) {
            issue("critical", true, "open");
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
        scan(null, container.getId(), "completed");
        for (int i = 0; i < 2; i++) {
            IssueEntity high = issue("high", false, "open");
            high.setRepoId(null);
            high.setContainerId(container.getId());
            issues.save(high);
        }
        issue("critical", false, "open"); // the repository's, not the container's

        SecurityScorecard card = scorecards.getContainerScorecard(container.getId(), Visibility.everything()).orElseThrow();

        assertThat(card.targetName()).isEqualTo("registry.example.invalid/shop:1.4.2");
        // 100 - 4 - 4 + 5: scanned, so observed and attested.
        assertThat(card.score()).isEqualTo(97);
        assertThat(card.openHighCount()).isEqualTo(2);
        assertThat(card.openCriticalCount()).isZero();
    }

    @Test
    @DisplayName("an unknown target has no scorecard, rather than a perfect one")
    void unknownTarget() {
        assertThat(scorecards.getRepositoryScorecard(repository.getId() + 1000, Visibility.everything())).isEmpty();
        assertThat(scorecards.getContainerScorecard(424242L, Visibility.everything())).isEmpty();
    }

    private SecurityScorecard scorecard() {
        return scorecards.getRepositoryScorecard(repository.getId(), Visibility.everything()).orElseThrow();
    }

    private void completedScan() {
        scan(repository.getId(), null, "completed");
    }

    private void scan(Long repoId, Long containerId, String status) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setContainerId(containerId);
        scan.setBranch("main");
        scan.setStatus(status);
        scan.setCreatedAt(Instant.now());
        scans.save(scan);
    }

    private RepositoryEntity anotherRepository(String name) {
        RepositoryEntity other = new RepositoryEntity();
        other.setName(name);
        other.setUrl("https://example.invalid/" + name + ".git");
        other.setBranch("main");
        return repositories.save(other);
    }

    private static VisibleScope scopeOf(ScanTarget... targets) {
        return new VisibleScope(VisibleScope.Kind.PROJECT, 1L, "Payments", List.of(targets), false);
    }

    private int fingerprints;

    private IssueEntity issue(String severity, boolean kev, String state) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repository.getId());
        issue.setType("vulnerability");
        issue.setSource("grype");
        issue.setSeverity(severity);
        issue.setState(state);
        issue.setFingerprint("fp-" + fingerprints++);
        issue.setKev(kev);
        issue.setTriageStatus("under_review");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        return issues.save(issue);
    }

    /** Written behind the entity's back: it has no setter for a column nothing computes. */
    private void markedReachable(IssueEntity issue) {
        jdbc.update("update t_issue set reachability = 'REACHABLE' where id = ?", issue.getId());
    }

    private void triaged(IssueEntity issue, String status) {
        issue.setTriageStatus(status);
        issues.save(issue);
    }

    private IssueEntity aged(IssueEntity issue, Instant firstSeenAt) {
        issue.setFirstSeenAt(firstSeenAt);
        return issues.save(issue);
    }

    private static LicenseEntry licence(Long targetId, String kind, boolean compliant) {
        return new LicenseEntry("pkg", "1.0", null, compliant ? "MIT" : "AGPL-3.0", null, compliant,
                compliant ? null : "disallowed", targetId, kind, "corp/payments");
    }

    private static VisibleTarget<ScanTarget.Repository> checked(ScanTarget.Repository target) {
        return RowVisibility.requireVisible(target, Visibility.everything());
    }
}
