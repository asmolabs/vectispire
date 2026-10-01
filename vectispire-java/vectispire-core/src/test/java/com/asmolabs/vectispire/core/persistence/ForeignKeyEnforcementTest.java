package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The foreign keys the schema declares, enforced by the engine the suite runs on.
 *
 * <p><b>MySQL discards a column-level {@code references}</b>, so a key that exists only inline in a
 * migration exists on PostgreSQL and nowhere else; on SQLite, which this suite ran on until decision
 * 0034, none is enforced without a pragma on each connection ({@code SqliteForeignKeysTest}). Either
 * way the failure is silent:
 * nothing errors, the constraints simply stop being checked and orphans start accumulating in tables
 * nothing reads. The one existing test that fabricated a {@code scan_id} out of a literal passed
 * happily for as long as the keys were absent, which is exactly how this reads when it regresses.
 */
@DisplayName("the foreign keys the schema declares are enforced")
class ForeignKeyEnforcementTest extends VectispireContextTest {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private FindingRepository findings;

    @Test
    @DisplayName("a row cannot name a parent that does not exist")
    void anOrphanIsRefused() {
        FindingEntity orphan = new FindingEntity();
        orphan.setScanId(9_999_999L);
        orphan.setType(FindingType.VULNERABILITY.wireName());
        orphan.setIdentifier("CVE-2021-44228");
        orphan.setSeverity(Severity.HIGH.wireName());
        orphan.setPackageName("log4j-core");
        orphan.setSource("grype");
        orphan.setCreatedAt(Instant.now());

        assertThatThrownBy(() -> findings.saveAndFlush(orphan))
                .as("a finding of a scan that never existed is unreachable from every query path "
                        + "in the product, and used to be accepted without complaint")
                .hasMessageContaining("FOREIGN KEY");
    }

    @Test
    @DisplayName("deleting a scan takes its findings with it, without the application saying so")
    void theCascadeRuns() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("ssh://git@example.com/team/app.git");
        repository.setName("app");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        long scanId = scans.save(scan).getId();

        FindingEntity finding = new FindingEntity();
        finding.setScanId(scanId);
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setIdentifier("CVE-2021-44228");
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setPackageName("log4j-core");
        finding.setSource("grype");
        finding.setCreatedAt(Instant.now());
        findings.saveAndFlush(finding);

        // Deleted through the scan alone: the `TargetDeleted` listeners remove children explicitly and
        // would hide the question. What is under test is what happens when nobody remembers to —
        // a crash between two deletes, a repair run at the prompt, a path added later.
        scans.deleteById(scanId);

        assertThat(findings.findByScanId(scanId))
                .as("the cascade the schema declares, actually running")
                .isEmpty();
    }
}
