package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The two column reads that replaced loading every scan to answer a question about targets.
 *
 * <p>They exist for their cost — no SBOM, no CVE payload — which a test cannot see; what it can
 * pin is that they answer the same question the entity read did, and in the order the evidence
 * bundle relies on.
 */
@DisplayName("reading scans as columns")
class ScanProjectionsDatabaseTest extends VectispireContextTest {

    @Autowired
    private Scans scans;

    @Autowired
    private GitRepositories repositories;

    @Test
    @DisplayName("each target with a completed scan appears once, however many scans it has")
    void targetsAreDistinct() {
        long repo = repository();
        scan(repo, ScanStatus.COMPLETED, "2026-09-01T10:00:00Z");
        scan(repo, ScanStatus.COMPLETED, "2026-09-02T10:00:00Z");
        scan(repo, ScanStatus.FAILED, "2026-09-03T10:00:00Z");

        List<Object[]> targets = scans.targetsWithStatus(ScanStatus.COMPLETED.wireName());

        assertThat(targets).hasSize(1);
        assertThat(((Number) targets.getFirst()[0]).longValue()).isEqualTo(repo);
        assertThat(targets.getFirst()[1]).isNull();
    }

    @Test
    @DisplayName("the evidence bundle's scans come newest first, not oldest")
    void newestFirst() {
        // Read through `findAll()`, the bundle kept the first twenty it met — the oldest scans of
        // the deployment's life, and never the current ones.
        long repo = repository();
        long old = scan(repo, ScanStatus.COMPLETED, "2026-01-01T10:00:00Z");
        long recent = scan(repo, ScanStatus.COMPLETED, "2026-09-01T10:00:00Z");
        long middle = scan(repo, ScanStatus.COMPLETED, "2026-05-01T10:00:00Z");

        assertThat(scans.idsAndTargetsNewestFirst(ScanStatus.COMPLETED.wireName()))
                .extracting(row -> ((Number) row[0]).longValue())
                .containsExactly(recent, middle, old);
    }

    private long repository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/r.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long scan(long repoId, ScanStatus status, String createdAt) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus(status.wireName());
        scan.setBranch("main");
        scan.setCreatedAt(Instant.parse(createdAt));
        return scans.save(scan).getId();
    }
}
