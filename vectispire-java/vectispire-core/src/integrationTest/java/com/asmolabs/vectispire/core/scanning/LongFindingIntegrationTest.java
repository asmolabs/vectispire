package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.scanners.DependencyScanner.DependencyFinding;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.scanning.persistence.Findings;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.Scans;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
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
 *
 * <p><b>Through the whole ingestion</b>, since the two tables are clipped by two modules: the scan's
 * findings by {@code scanning}, the issues by the backlog, each after the fingerprint was computed on
 * the whole value (decision 0029). It drove the sync alone while the sync wrote both.
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
    private ScanIngestor ingestor;

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

        String path = "src/" + "d/".repeat(400) + "index.js";
        ScanArtifacts artifacts = ScanArtifacts.builder()
                .dependencies(List.of(new DependencyFinding(
                        "GHSA-" + "x".repeat(300),
                        Severity.HIGH,
                        "left-pad",
                        "1.0.0",
                        "1." + "0".repeat(400),
                        null,
                        "https://advisories.example/" + "l".repeat(600),
                        "pkg:npm/" + "p".repeat(600))))
                .secrets(List.of(new SecretFinding("aws-key", "AWS token", path, 12, "abc")))
                .build(Duration.ZERO);

        ScanIngestor.Reconciliation result = transactions.execute(status ->
                ingestor.ingest(scans.findById(saved.getId()).orElseThrow(), artifacts));

        assertThat(result.created()).isEqualTo(2);
        assertThat(findings.findAll()).hasSize(2).allSatisfy(stored -> {
            if (stored.getPurl() != null) {
                assertThat(stored.getPurl()).hasSize(255);
                assertThat(stored.getLink()).hasSize(500);
            } else {
                assertThat(stored.getFilePath()).hasSize(500);
            }
        });
        assertThat(issues.findAll()).hasSize(2).extracting(IssueEntity::getIdentifier)
                .allSatisfy(identifier -> assertThat(identifier.length()).isLessThanOrEqualTo(255));
    }
}
