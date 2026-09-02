package com.asmolabs.vectispire.core.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * The pragma that makes SQLite's foreign keys mean something.
 *
 * <p><b>SQLite records an {@code on delete cascade} and enforces nothing</b> until a connection
 * issues {@code PRAGMA foreign_keys = ON}. Nothing issued it, so on the fixture engine — and on
 * any single-file deployment — every cascade in the schema was decoration. {@code
 * SqliteForeignKeys} sets it as Hikari init SQL, on each connection as it is opened, because the
 * pragma is per connection and a migration's connection is not the one serving requests.
 *
 * <p><b>Why a test and not a settled config line.</b> A pool setting is one refactor away from
 * being dropped, and the failure is silent: nothing errors, the constraints simply stop being
 * checked and orphans start accumulating in tables nothing reads. The one existing test that
 * fabricated a {@code scan_id} out of a literal passed happily for as long as the pragma was
 * absent, which is exactly how this reads when it regresses.
 */
@DisplayName("the foreign keys the schema declares are enforced")
class ForeignKeyEnforcementTest extends VectispireContextTest {

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Findings findings;

    @Test
    @DisplayName("the pragma is on, on a connection the pool handed out")
    void thePragmaIsOn() {
        // Asked of a pooled connection rather than of the configuration, because the setting is
        // only worth anything if it survived the trip through Hikari.
        assertThat(jdbc.queryForObject("pragma foreign_keys", Integer.class))
                .as("SQLite enforces nothing without it, whatever the schema declares")
                .isEqualTo(1);
    }

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

        // Deleted through the scan alone: `TargetDeletionService` removes children explicitly and
        // would hide the question. What is under test is what happens when nobody remembers to —
        // a crash between two deletes, a repair run at the prompt, a path added later.
        scans.deleteById(scanId);

        assertThat(findings.findByScanId(scanId))
                .as("the cascade the schema declares, actually running")
                .isEmpty();
    }
}
