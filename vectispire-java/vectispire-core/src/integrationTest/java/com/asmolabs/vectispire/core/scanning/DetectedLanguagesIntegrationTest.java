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
 * column, and the lookup the repository list and the solutions tree make for every visible repository;
 * and each scan's own record, V58's column beside it, which a checklist reads by scan.
 *
 * <p>The identifiers are the estate's, which the data sizes: one bind parameter each, so a statement
 * past 65,535 fails unless the catalogue batches — this asks for seventy thousand. PostgreSQL is the
 * engine that refuses the unbatched statement ("at most 65 535 parameters"); MySQL's client-side
 * statements accept it, so a green run on MySQL alone says nothing of the batching.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the languages of each repository's newest completed scan")
class DetectedLanguagesIntegrationTest {

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

    /**
     * A scan's own record of languages — its census and its SAST rules' (V58), read by a checklist on the
     * scan a measurement rests on. Same limit, same engine to prove it: PostgreSQL.
     */
    @Test
    @DisplayName("each scan's census and SAST rules' languages by scan id, past the bind limit, null kept unknown")
    void eachScansLanguages() {
        long repository = repository("scanned");
        long both = scan(repository, ScanStatus.COMPLETED, "java,yaml");
        scans.recordSastLanguages(both, "java,python");
        long neither = scan(repository, ScanStatus.COMPLETED, null);
        long counted = scan(repository, ScanStatus.COMPLETED, "");
        scans.recordSastLanguages(counted, "");

        List<Long> ids = new ArrayList<>();
        ids.add(both);
        ids.addAll(LongStream.rangeClosed(1_000_000, 1_070_000).boxed().toList());
        ids.addAll(List.of(neither, counted));

        Map<Long, ScanCatalog.ScanLanguages> languages = catalog.languagesOf(ids);

        assertThat(languages).containsOnlyKeys(both, neither, counted);
        assertThat(languages.get(both).detected()).contains(Set.of(Language.JAVA, Language.YAML));
        assertThat(languages.get(both).sastRules()).contains(Set.of(Language.JAVA, Language.PYTHON));
        assertThat(languages.get(neither).detected()).as("null is unknown").isEmpty();
        assertThat(languages.get(neither).sastRules()).isEmpty();
        assertThat(languages.get(counted).detected()).as("the empty string is none").contains(Set.of());
        assertThat(languages.get(counted).sastRules()).contains(Set.of());
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + ".git");
        repository.setName(name);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long scan(long repositoryId, ScanStatus status, String languages) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setAttempts(1);
        scan.setDetectedLanguages(languages);
        return scans.save(scan).getId();
    }
}
