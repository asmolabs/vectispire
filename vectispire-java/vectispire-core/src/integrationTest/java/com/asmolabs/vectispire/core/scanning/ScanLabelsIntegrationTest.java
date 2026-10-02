package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.LongStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * Each scan's branch and project version by scan id — what the component search asks of {@code
 * ScanCatalog} since its rows stopped joining the scans' table (V61).
 *
 * <p>The search hands it the scans of one page, at most the cap and one; the catalogue takes any
 * collection, so it asks a thousand at a time like every lookup there, and this hands it seventy
 * thousand identifiers. The limit is <b>PostgreSQL's alone</b> — its driver refuses a statement past
 * 65,535 parameters; MySQL's client-side statements accept one — so a green run on MySQL proves the
 * query, not the batching.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("each scan's branch and project version, by scan id")
class ScanLabelsIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private ScanCatalog catalog;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Test
    @DisplayName("past every engine's bind limit: each scan's own, a version never read kept null, the absent left out")
    void eachScansLabel() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/labels.git");
        repository.setName("labels");
        repository.setBranch("main");
        long repositoryId = repositories.save(repository).getId();
        long released = scan(repositoryId, "main", "1.17.6");
        long unversioned = scan(repositoryId, "feature/x", null);

        // The real scans among seventy thousand identifiers no row carries, first and last.
        List<Long> ids = new ArrayList<>();
        ids.add(released);
        ids.addAll(LongStream.rangeClosed(3_000_000, 3_070_000).boxed().toList());
        ids.add(unversioned);

        Map<Long, ScanCatalog.ScanLabel> labels = catalog.labelsOf(ids);

        assertThat(labels).containsOnlyKeys(released, unversioned);
        assertThat(labels.get(released)).isEqualTo(new ScanCatalog.ScanLabel("main", "1.17.6"));
        assertThat(labels.get(unversioned)).isEqualTo(new ScanCatalog.ScanLabel("feature/x", null));
    }

    private long scan(long repositoryId, String branch, String version) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch(branch);
        scan.setVersion(version);
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setAttempts(1);
        return scans.save(scan).getId();
    }
}
