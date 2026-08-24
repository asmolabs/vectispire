package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Reconciliation against a real database.
 *
 * <p>The unit suite proves the rules with fakes; this proves the <b>queries</b>. The one that
 * matters is {@code findOpenByTarget}, whose {@code :repoId is not null} shape is the kind of
 * JPQL that behaves as intended against a fake and differently against SQL — and whose failure
 * mode is the worst this system has: resolving a type's entire history in silence.
 */
@DisplayName("folding findings into the backlog, against a database")
class IssueSyncDatabaseTest extends VectispireContextTest {

    @Autowired
    private IssueSyncService sync;

    @Autowired
    private Issues issues;

    @Autowired
    private Scans scans;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private TransactionTemplate transactions;

    private long repositoryId;
    private long otherRepositoryId;

    @BeforeEach
    void seedTargets() {
        repositoryId = repository("https://example.invalid/one.git");
        otherRepositoryId = repository("https://example.invalid/two.git");
    }

    @Test
    @DisplayName("a first scan opens an issue per finding")
    void firstScanOpensIssues() {
        ScanEntity scan = scan(repositoryId);

        IssueSyncService.SyncResult result = reconcile(
                scan, List.of(vulnerability(scan, "CVE-1"), vulnerability(scan, "CVE-2")),
                Set.of(FindingType.VULNERABILITY));

        assertThat(result.created()).isEqualTo(2);
        assertThat(openIdentifiers(repositoryId)).containsExactlyInAnyOrder("CVE-1", "CVE-2");
    }

    @Test
    @DisplayName("seeing the same finding again keeps one issue, and its history")
    void secondScanDoesNotDuplicate() {
        ScanEntity first = scan(repositoryId);
        reconcile(first, List.of(vulnerability(first, "CVE-1")), Set.of(FindingType.VULNERABILITY));

        ScanEntity second = scan(repositoryId);
        IssueSyncService.SyncResult result =
                reconcile(second, List.of(vulnerability(second, "CVE-1")), Set.of(FindingType.VULNERABILITY));

        assertThat(result.created()).isZero();
        assertThat(result.stillOpen()).isEqualTo(1);
        assertThat(issues.findAll()).hasSize(1);
        assertThat(issues.findAll().getFirst().getTimesSeen()).isEqualTo(2);
    }

    @Test
    @DisplayName("a scan that looked and did not find resolves what it looked for")
    void lookingAndFindingNothingResolves() {
        ScanEntity first = scan(repositoryId);
        reconcile(first, List.of(vulnerability(first, "CVE-1")), Set.of(FindingType.VULNERABILITY));

        ScanEntity second = scan(repositoryId);
        IssueSyncService.SyncResult result = reconcile(second, List.of(), Set.of(FindingType.VULNERABILITY));

        assertThat(result.resolved()).isEqualTo(1);
        assertThat(openIdentifiers(repositoryId)).isEmpty();
    }

    @Test
    @DisplayName("a type nobody looked at is left alone")
    void notLookingResolvesNothing() {
        ScanEntity first = scan(repositoryId);
        reconcile(first, List.of(vulnerability(first, "CVE-1")), Set.of(FindingType.VULNERABILITY));

        // The whole of decision 0007, executed: a scan whose dependency step failed declares no
        // type, and the backlog must survive it untouched.
        ScanEntity second = scan(repositoryId);
        IssueSyncService.SyncResult result = reconcile(second, List.of(), Set.of());

        assertThat(result.resolved()).isZero();
        assertThat(openIdentifiers(repositoryId)).containsExactly("CVE-1");
    }

    @Test
    @DisplayName("one target's scan never resolves another target's backlog")
    void theTargetFilterHoldsInSql() {
        ScanEntity mine = scan(repositoryId);
        reconcile(mine, List.of(vulnerability(mine, "CVE-1")), Set.of(FindingType.VULNERABILITY));
        ScanEntity theirs = scan(otherRepositoryId);
        reconcile(theirs, List.of(vulnerability(theirs, "CVE-1")), Set.of(FindingType.VULNERABILITY));

        // `findOpenByTarget` takes both ids and uses whichever is set. Against a fake that works
        // by construction; against SQL it is a condition somebody has to have written correctly,
        // and getting it wrong wipes every other target's backlog on the next scan.
        ScanEntity again = scan(repositoryId);
        reconcile(again, List.of(), Set.of(FindingType.VULNERABILITY));

        assertThat(openIdentifiers(repositoryId)).isEmpty();
        assertThat(openIdentifiers(otherRepositoryId)).containsExactly("CVE-1");
    }

    @Test
    @DisplayName("a resolved issue that comes back reopens, and loses only a \"fixed\" triage")
    void reopeningKeepsAHumanJudgment() {
        ScanEntity first = scan(repositoryId);
        reconcile(first, List.of(vulnerability(first, "CVE-1")), Set.of(FindingType.VULNERABILITY));

        IssueEntity stored = issues.findAll().getFirst();
        stored.setTriageStatus(TriageStatus.NOT_AFFECTED.wireName());
        stored.setTriageJustification("component_not_present");
        issues.save(stored);

        reconcile(scan(repositoryId), List.of(), Set.of(FindingType.VULNERABILITY));
        ScanEntity third = scan(repositoryId);
        IssueSyncService.SyncResult back =
                reconcile(third, List.of(vulnerability(third, "CVE-1")), Set.of(FindingType.VULNERABILITY));

        assertThat(back.reopened()).isEqualTo(1);
        // "Not affected" is a claim about a context, and the context did not change because a
        // scanner saw the component again. Only "fixed" is contradicted by its return.
        assertThat(issues.findAll().getFirst().getTriageStatus())
                .isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
    }

    private IssueSyncService.SyncResult reconcile(
            ScanEntity scan, List<FindingEntity> findings, Set<FindingType> scanned) {
        // `sync` is MANDATORY: it refuses to run outside a transaction, which is the guarantee
        // that its writes commit with the scan's. Opening one here is what a caller does.
        return transactions.execute(status -> sync.sync(scan, findings, scanned, Map.of(), result -> {}));
    }

    private List<String> openIdentifiers(long repoId) {
        return issues.findAll().stream()
                .filter(issue -> repoId == issue.getRepoId())
                .filter(issue -> IssueState.OPEN.wireName().equals(issue.getState()))
                .map(IssueEntity::getIdentifier)
                .toList();
    }

    private long repository(String url) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl(url);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private ScanEntity scan(long repoId) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.SCANNING.wireName());
        scan.setCreatedAt(Instant.now());
        return scans.save(scan);
    }

    private static FindingEntity vulnerability(ScanEntity scan, String identifier) {
        FindingEntity finding = new FindingEntity();
        finding.setScanId(scan.getId());
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setIdentifier(identifier);
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setSource("grype");
        finding.setPackageName("openssl");
        finding.setCreatedAt(Instant.now());
        finding.setIsKev(false);
        return finding;
    }
}
