package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.VectispireContextTest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * What the backlog says under an identifier.
 *
 * <p><b>Every non-vulnerability arrived with no description at all.</b> The text came from a
 * lookup keyed by identifier, which holds advisory prose — so a CVE found its paragraph and a
 * secret asking for {@code generic-api-key}, or a Checkov control asking for {@code CKV2_GHA_1},
 * found nothing. The scanner had supplied a usable sentence, it was written to the finding, and
 * the issue ignored it.
 *
 * <p>On a real scan of this repository that produced seven findings whose entire content was a
 * rule id and a file path.
 */
@DisplayName("the description an issue carries")
class IssueDescriptionTest extends VectispireContextTest {

    @Autowired
    private IssueSyncService sync;

    /**
     * `sync` is `MANDATORY`: it must join a transaction the caller opened. Deliberately, so that
     * the reconciliation and the outbox message it produces commit together — see `OutboxService`.
     */
    @Autowired
    private org.springframework.transaction.support.TransactionTemplate transactions;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Issues issues;

    @Test
    @DisplayName("falls back to what the scanner said, when no advisory exists")
    void theScannerSentenceIsKept() {
        ScanEntity scan = seedScan();

        transactions.executeWithoutResult(status -> sync.sync(
                scan,
                List.of(
                        finding(scan, FindingType.SECRET, "generic-api-key",
                                "Detected a Generic API Key, potentially exposing access to various services."),
                        finding(scan, FindingType.IAC, "CKV2_GHA_1",
                                "Ensure top-level permissions are not set to write-all")),
                java.util.Set.of(FindingType.SECRET, FindingType.IAC),
                Map.of(),
                result -> {}));

        assertThat(issues.findAll())
                .extracting(IssueEntity::getIdentifier, IssueEntity::getDescription)
                .containsExactlyInAnyOrder(
                        org.assertj.core.groups.Tuple.tuple(
                                "generic-api-key",
                                "Detected a Generic API Key, potentially exposing access to various services."),
                        org.assertj.core.groups.Tuple.tuple(
                                "CKV2_GHA_1", "Ensure top-level permissions are not set to write-all"));
    }

    @Test
    @DisplayName("prefers the advisory, which says more than a one-line summary")
    void theAdvisoryWins() {
        ScanEntity scan = seedScan();

        transactions.executeWithoutResult(status -> sync.sync(
                scan,
                List.of(finding(scan, FindingType.VULNERABILITY, "CVE-2026-1", "short summary from the scanner")),
                java.util.Set.of(FindingType.VULNERABILITY),
                Map.of("CVE-2026-1", "The full advisory, with the conditions under which it applies."),
                result -> {}));

        assertThat(issues.findAll())
                .singleElement()
                .extracting(IssueEntity::getDescription)
                .isEqualTo("The full advisory, with the conditions under which it applies.");
    }

    private ScanEntity seedScan() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/described.git");
        repository.setBranch("main");
        long repositoryId = repositories.save(repository).getId();

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus("scanning");
        scan.setCreatedAt(Instant.now());
        return scans.save(scan);
    }

    private static FindingEntity finding(ScanEntity scan, FindingType type, String identifier, String description) {
        FindingEntity finding = new FindingEntity();
        finding.setScanId(scan.getId());
        finding.setType(type.wireName());
        finding.setIdentifier(identifier);
        finding.setSeverity("high");
        finding.setSource("test");
        finding.setDescription(description);
        finding.setCreatedAt(Instant.now());
        return finding;
    }
}
