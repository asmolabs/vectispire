package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.plugins.Language;
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
import java.util.Optional;
import java.util.Set;
import java.util.stream.LongStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * Each repository's newest completed scan and the languages it recorded, on a real engine — V57's
 * column, and the lookup the repository list and the solutions tree make for every visible repository.
 *
 * <p>The identifiers are the estate's, which the data sizes: one bind parameter each, so a statement
 * past 65,535 fails unless the catalogue batches — this asks for seventy thousand. PostgreSQL is the
 * engine that refuses the unbatched statement ("at most 65 535 parameters"); MySQL's client-side
 * statements and the SQLite driver accept it, so a green run on those two alone says nothing of the
 * batching.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the languages of each repository's newest completed scan")
class DetectedLanguagesIntegrationTest {

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
    private ScanCatalog catalog;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @BeforeEach
    void empty() {
        scans.deleteAll();
        repositories.deleteAll();
    }

    @Test
    @DisplayName("past every engine's bind limit: the newest completed scan answers, unknown stays unknown")
    void theNewestCompletedScanAnswers() {
        long current = repository("current");
        scan(current, ScanStatus.COMPLETED, "java");
        scan(current, ScanStatus.COMPLETED, "java,typescript");
        scan(current, ScanStatus.FAILED, "go");
        long forgotten = repository("forgotten");
        scan(forgotten, ScanStatus.COMPLETED, "python");
        scan(forgotten, ScanStatus.COMPLETED, null);
        long empty = repository("empty");
        scan(empty, ScanStatus.COMPLETED, "");
        long never = repository("never");

        // The real repositories among seventy thousand identifiers no row carries, first and last.
        List<Long> ids = new ArrayList<>();
        ids.add(current);
        ids.addAll(LongStream.rangeClosed(1_000_000, 1_070_000).boxed().toList());
        ids.addAll(List.of(forgotten, empty, never));

        Map<Long, Set<Language>> detected = catalog.newestDetectedLanguages(ids);

        assertThat(detected).containsOnlyKeys(current, empty);
        assertThat(detected.get(current)).containsExactlyInAnyOrder(Language.JAVA, Language.TYPESCRIPT);
        assertThat(detected.get(empty)).isEmpty();
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + ".git");
        repository.setName(name);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private void scan(long repositoryId, ScanStatus status, String languages) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setAttempts(1);
        scan.setDetectedLanguages(languages);
        scans.save(scan);
    }
}
