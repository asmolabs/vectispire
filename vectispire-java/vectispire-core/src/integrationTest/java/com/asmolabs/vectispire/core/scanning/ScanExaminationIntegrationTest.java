package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.scanning.persistence.queries.ExaminingScanRow;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
 * A repository's newest scan in which a built-in step produced, on a real engine (decision 0032, §6).
 *
 * <p>Two things only a server can say. The match — the column wrapped in commas, then {@code like} —
 * leans on {@code concat} and on a null column concatenating to null, and each engine spells both its
 * own way. And the identifiers come from a project's repositories, which the data sizes: one bind
 * parameter each, a statement past 65,535 fails unless the catalogue batches — so this asks for
 * seventy thousand. PostgreSQL is the engine that
 * refuses the unbatched statement here ("at most 65 535 parameters"); MySQL's client-side statements
 * accept it, so a green run on MySQL alone says nothing of the batching.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the newest scan that examined a type")
class ScanExaminationIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    private static final Instant SINCE = Instant.parse("2026-09-01T00:00:00Z");

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
    @DisplayName("past every engine's bind limit, only a completed scan that recorded the type within the age counts")
    void onlyWhatRecordedTheTypeCounts() {
        long examined = repository("examined");
        scan(examined, ScanStatus.COMPLETED, "quality,sast", SINCE.plus(Duration.ofDays(1)));
        long newest = scan(examined, ScanStatus.COMPLETED, "sast", SINCE.plus(Duration.ofDays(2)));
        // Newer, and its source analysis was absent: it is not the evidence, the one before it is.
        scan(examined, ScanStatus.COMPLETED, "secret", SINCE.plus(Duration.ofDays(3)));

        long otherType = repository("other-type");
        scan(otherType, ScanStatus.COMPLETED, "iac,quality,secret", SINCE.plus(Duration.ofDays(1)));
        long unrecorded = repository("unrecorded");
        scan(unrecorded, ScanStatus.COMPLETED, null, SINCE.plus(Duration.ofDays(1)));
        long nothing = repository("nothing");
        scan(nothing, ScanStatus.COMPLETED, "", SINCE.plus(Duration.ofDays(1)));
        long failed = repository("failed");
        scan(failed, ScanStatus.FAILED, "sast", SINCE.plus(Duration.ofDays(1)));
        long stale = repository("stale");
        scan(stale, ScanStatus.COMPLETED, "sast", SINCE.minus(Duration.ofDays(1)));

        // The real repositories among seventy thousand identifiers no row carries, first and last.
        List<Long> ids = new ArrayList<>();
        ids.add(examined);
        ids.addAll(LongStream.rangeClosed(1_000_000, 1_070_000).boxed().toList());
        ids.addAll(List.of(otherType, unrecorded, nothing, failed, stale));

        Map<Long, ExaminingScanRow> found = catalog.newestExamining(ids, FindingType.SAST, SINCE);

        assertThat(found).containsOnlyKeys(examined);
        assertThat(found.get(examined).scanId()).isEqualTo(newest);
        assertThat(found.get(examined).createdAt()).isEqualTo(SINCE.plus(Duration.ofDays(2)));

        // One whole name, never a longer one holding it: `quality` is in the first row of `other-type`,
        // `secret` in the newest of `examined`.
        assertThat(catalog.newestExamining(ids, FindingType.QUALITY, SINCE)).containsOnlyKeys(examined, otherType);
        assertThat(catalog.newestExamining(ids, FindingType.SECRET, SINCE).get(examined).createdAt())
                .isEqualTo(SINCE.plus(Duration.ofDays(3)));
    }

    @Test
    @DisplayName("a tool-scoped type is refused rather than answered 'never examined'")
    void toolScopedTypesAreRefused() {
        assertThatThrownBy(() -> catalog.newestExamining(List.of(1L), FindingType.PLUGIN, SINCE))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(catalog.newestExamining(List.of(), FindingType.SAST, SINCE)).isEmpty();
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + ".git");
        repository.setName(name);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long scan(long repositoryId, ScanStatus status, String examinedTypes, Instant createdAt) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(createdAt);
        scan.setAttempts(1);
        scan.setExaminedTypes(examinedTypes);
        return scans.save(scan).getId();
    }
}
