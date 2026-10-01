package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.scanning.ObservedFindings;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
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
 * The scan's pre-commit hook, inside a real transaction (decision 0033, lot 1).
 *
 * <p>{@code IssueSyncServiceTest} said a throwing hook "does not cost the scan its results", and
 * was green — against mocks, with no transaction at all. What the claim depends on is a
 * transaction manager: the hook the scan installs queues notifications through
 * {@code OutboxService.enqueue}, a {@code MANDATORY} proxy, and an exception leaving a proxy that
 * <i>participates</i> in a transaction marks the whole transaction rollback-only. The catch in
 * {@code IssueSyncService} kept nothing: the commit answered {@code UnexpectedRollbackException}
 * and the scan was abandoned. Only a database could say so. The catch is gone, and what is pinned
 * here is the behaviour that was always true — the scan and its notifications commit together or
 * not at all.
 */
@DisplayName("the scan's pre-commit hook, inside a real transaction")
class IssueSyncHookDatabaseTest extends VectispireContextTest {

    @Autowired
    private IssueSyncService sync;

    @Autowired
    private OutboxService outbox;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private OutboxMessageRepository messages;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private TransactionTemplate transactions;

    private long repositoryId;
    private long scanId;

    @BeforeEach
    void target() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://git.example.test/hook.git");
        repository.setName("hook");
        repository.setBranch("main");
        repositoryId = repositories.save(repository).getId();

        // The scan the issues will name as first seen: `t_issue.first_seen_scan_id` is a foreign key.
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.SCANNING.wireName());
        scan.setCreatedAt(Instant.parse("2026-10-01T10:00:00Z"));
        scanId = scans.save(scan).getId();
    }

    @Test
    @DisplayName("a hook whose transactional call throws takes the scan's results with it, and leaves nothing half-written")
    void aFailingHookRollsTheScanBack() {
        // The failure is the real one's shape, not a lambda that throws by itself: the exception
        // leaves `OutboxService.enqueue`, a proxy taking part in the scan's transaction — a string
        // is not an object, so the payload cannot be stamped with its message id. Before decision
        // 0033's first lot a catch claimed the results were kept; the commit answered
        // `UnexpectedRollbackException` instead, and this test is what found it.
        assertThatThrownBy(() -> transactions.executeWithoutResult(status -> sync.sync(
                        scanId,
                        new ScanTarget.Repository(repositoryId),
                        ObservedFindings.of(List.of(secret("aws-access-token"))),
                        Set.of(FindingType.SECRET),
                        Map.of(),
                        result -> outbox.enqueue("not an object", OutboxService.TYPE_SCAN_DELTA))))
                .as("the failure reaches the caller, which abandons the scan as transient and retries it")
                .isInstanceOf(RuntimeException.class);

        assertThat(issues.findAll()).as("no issue survives a rolled-back scan").isEmpty();
        assertThat(messages.findAll()).as("and no notification announces one").isEmpty();
    }

    @Test
    @DisplayName("a hook that succeeds commits its notification with the issue it announces")
    void aSucceedingHookCommitsWithTheScan() {
        transactions.executeWithoutResult(status -> sync.sync(
                scanId,
                new ScanTarget.Repository(repositoryId),
                ObservedFindings.of(List.of(secret("aws-access-token"))),
                Set.of(FindingType.SECRET),
                Map.of(),
                result -> outbox.enqueue(Map.of("scan_id", scanId), OutboxService.TYPE_SCAN_DELTA)));

        assertThat(issues.findAll()).hasSize(1);
        assertThat(messages.findAll()).hasSize(1);
    }

    private static FindingEntity secret(String identifier) {
        FindingEntity finding = new FindingEntity();
        finding.setType(FindingType.SECRET.wireName());
        finding.setIdentifier(identifier);
        finding.setSource("gitleaks");
        finding.setSeverity("high");
        finding.setFilePath("config/prod.env");
        finding.setCreatedAt(Instant.parse("2026-10-01T10:00:00Z"));
        return finding;
    }
}
