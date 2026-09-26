package com.asmolabs.vectispire.core.services.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * A scan result carrying values longer than their columns, written to a real engine.
 *
 * <p><b>What this is for.</b> A purl, a path, a fix-version list or an advisory link past its
 * column failed the flush of the whole scan on MySQL and PostgreSQL — every finding of every type
 * lost for one long value. SQLite enforces no length, so the unit suite could only check that the
 * values are clipped; this checks that the flush now goes through where it used to fail.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("an oversized scan result on a real engine")
class LongFindingIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    @BeforeAll
    static void start() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::start);
    }

    @AfterAll
    static void stop() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private IssueSyncService sync;

    @Autowired
    private Issues issues;

    @Autowired
    private Findings findings;

    @Autowired
    private Scans scans;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private TransactionTemplate transactions;

    @Test
    @DisplayName("one long purl, path and link no longer lose the scan")
    void theFlushGoesThrough() {
        findings.deleteAll();
        issues.deleteAll();
        scans.deleteAll();
        repositories.deleteAll();

        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("ssh://git@example.com/team/long.git");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.SCANNING.wireName());
        scan.setCreatedAt(Instant.now());
        ScanEntity saved = scans.save(scan);

        FindingEntity finding = new FindingEntity();
        finding.setScanId(saved.getId());
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setIdentifier("GHSA-" + "x".repeat(300));
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setSource("grype");
        finding.setPackageName("left-pad");
        finding.setPurl("pkg:npm/" + "p".repeat(600));
        finding.setFilePath("src/" + "d/".repeat(400) + "index.js");
        finding.setFixVersions("1." + "0".repeat(400));
        finding.setLink("https://advisories.example/" + "l".repeat(600));
        finding.setCreatedAt(Instant.now());
        finding.setIsKev(false);

        IssueSyncService.SyncResult result = transactions.execute(status ->
                sync.sync(saved, List.of(finding), Set.of(FindingType.VULNERABILITY), Map.of(), ignored -> {}));

        assertThat(result.created()).isEqualTo(1);
        assertThat(findings.findAll()).singleElement()
                .satisfies(stored -> assertThat(stored.getPurl()).hasSize(255));
    }
}
