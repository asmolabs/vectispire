package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.sbom.BuildSbom;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.inventory.internal.BuildSbomRetentionTask;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomComponentRepository;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The build SBOMs, purged by the evidence window, against a database: the import and its components go,
 * the inventory a scan was completed with stays, and zero purges nothing.
 */
@DisplayName("the build SBOMs' retention, against a database")
class BuildSbomRetentionDatabaseTest extends VectispireContextTest {

    @Autowired
    private BuildSbomInventory builds;

    @Autowired
    private BuildSbomRetentionTask task;

    @Autowired
    private BuildSbomRepository imports;

    @Autowired
    private BuildSbomComponentRepository listed;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private SettingsService settings;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private TransactionTemplate transactions;

    private long ledger;

    @BeforeEach
    void seed() {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("ssh://git@example.com/team/ledger.git");
        entity.setName("ledger");
        entity.setBranch("main");
        ledger = repositories.save(entity).getId();
    }

    private long imported(Instant at, String library) {
        BuildSbom sbom = new BuildSbom("1.6", java.util.Optional.empty(), List.of(
                new BuildSbom.Component(library, "1.0", "pkg:maven/org.example/" + library + "@1.0", "library", null)));
        return transactions.execute(status -> builds.record(new BuildSbomInventory.Accepted(1L, "ledger-ci", ledger,
                null, null, "0".repeat(64), at, "pipeline", UUID.randomUUID()), sbom)).id();
    }

    @Test
    @DisplayName("removes the imports past the window and their components, keeps the rest; zero purges nothing")
    void purgesPastTheWindow() {
        Instant now = Instant.now();
        long old = imported(now.minus(Duration.ofDays(40)), "aged");
        long recent = imported(now.minus(Duration.ofDays(10)), "recent");

        settings.set(Setting.EVIDENCE_RETENTION_DAYS, "0");
        task.run();
        assertThat(imports.findAll()).as("zero purges nothing").hasSize(2);

        settings.set(Setting.EVIDENCE_RETENTION_DAYS, "30");
        task.run();
        assertThat(imports.findAll()).extracting(row -> row.getId()).containsExactly(recent);
        assertThat(listed.findByImportIdOrderByIdAsc(old)).isEmpty();
        assertThat(listed.findByImportIdOrderByIdAsc(recent)).hasSize(1);
    }

    @Test
    @DisplayName("a scan keeps the inventory an import gave it after the import is purged")
    void theScanKeepsWhatItWasGiven() {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(ledger);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setAttempts(1);
        long scanId = scans.save(scan).getId();
        ComponentEntity given = new ComponentEntity();
        given.setScanId(scanId);
        given.setRepoId(ledger);
        given.setName("aged");
        given.setVersion("1.0");
        given.setOrigin("build");
        long old = imported(Instant.now().minus(Duration.ofDays(40)), "aged");
        given.setBuildSbomId(old);
        components.save(given);

        settings.set(Setting.EVIDENCE_RETENTION_DAYS, "30");
        task.run();

        assertThat(imports.findById(old)).isEmpty();
        assertThat(components.findByScanId(scanId)).singleElement()
                .satisfies(row -> assertThat(row.getBuildSbomId()).isEqualTo(old));
    }
}
