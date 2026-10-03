package com.asmolabs.vectispire.core.inventory;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.sbom.BuildSbom;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomComponentRepository;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomEntity;
import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomRepository;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * A build SBOM completing a scan's inventory on a real engine (decision 0039): the V82 columns written
 * and read back, the scan's rows locked for the write, and two completions of one scan serialised.
 *
 * <p><b>The interleaving is forced.</b> The first completion runs inside a transaction held open after it
 * wrote; the second starts only then, and the first is released once the engine reports the second
 * waiting. Without the lock on the scan's rows the second read the rows as they were before the first,
 * waited only at its own update, and then added the build's components a second time.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("a build SBOM completing a scan, on the engine")
class BuildSbomCompletionIntegrationTest {

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
    private BuildSbomInventory builds;

    @Autowired
    private BuildSbomRepository imports;

    @Autowired
    private BuildSbomComponentRepository listed;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private PlatformTransactionManager transactions;

    private long repository;
    private long scan;

    @BeforeEach
    void scannedTree() {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("https://example.invalid/ledger-" + System.nanoTime() + ".git");
        entity.setBranch("main");
        repository = repositories.save(entity).getId();
        ScanEntity row = new ScanEntity();
        row.setRepoId(repository);
        row.setBranch("main");
        row.setStatus(ScanStatus.COMPLETED.wireName());
        row.setCreatedAt(Instant.now());
        row.setAttempts(1);
        row.setExaminedTypes("vulnerability");
        row.setSbom("{\"artifacts\":[]}");
        scan = scans.save(row).getId();
        scanned("spring-core", "UNKNOWN", "pkg:maven/org.springframework/spring-core");
        scanned("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0");
    }

    private void scanned(String name, String version, String purl) {
        ComponentEntity row = new ComponentEntity();
        row.setScanId(scan);
        row.setRepoId(repository);
        row.setScanCreatedAt(Instant.now());
        row.setName(name);
        row.setVersion(version);
        row.setPurl(purl);
        components.save(row);
    }

    private static final List<BuildSbom.Component> BUILT = List.of(
            new BuildSbom.Component("spring-core", "6.1.14", "pkg:maven/org.springframework/spring-core@6.1.14",
                    "library", "Apache-2.0"),
            new BuildSbom.Component("spring-jcl", "6.1.14", "pkg:maven/org.springframework/spring-jcl@6.1.14",
                    "library", "Apache-2.0"));

    private Map<String, String> inventory() {
        return components.findByScanId(scan).stream().collect(Collectors.toMap(
                ComponentEntity::getName,
                row -> row.getVersion() + " " + (row.getOrigin() == null ? "scanner" : row.getOrigin()) + " "
                        + row.getScannedVersion() + " " + row.getDeclaredLicense()));
    }

    @Test
    @DisplayName("an import completes the scan and a newer one without the package gives the scanner's row back")
    void completesAndRestores() {
        BuildSbomView first = new TransactionTemplate(transactions).execute(status -> builds.record(new BuildSbomInventory
                .Accepted(1L, "ledger-ci", repository, "4f2a9c1", "main", "a".repeat(64), Instant.now(), "pipeline",
                        UUID.randomUUID()), new BuildSbom("1.6", Optional.of("cyclonedx-maven-plugin 2.9.1"), BUILT)));

        assertThat(first.completedScanId()).isEqualTo(scan);
        assertThat(inventory()).containsExactlyInAnyOrderEntriesOf(Map.of(
                "spring-core", "6.1.14 both UNKNOWN Apache-2.0",
                "spring-jcl", "6.1.14 build null Apache-2.0",
                "left-pad", "1.3.0 scanner null null"));
        assertThat(builds.history(repository)).singleElement()
                .satisfies(view -> assertThat(view.completedScanId()).isEqualTo(scan));

        new TransactionTemplate(transactions).execute(status -> builds.record(new BuildSbomInventory.Accepted(1L,
                "ledger-ci", repository, null, null, "b".repeat(64), Instant.now(), "pipeline", UUID.randomUUID()),
                new BuildSbom("1.5", Optional.empty(), List.of())));
        assertThat(inventory()).containsExactlyInAnyOrderEntriesOf(Map.of(
                "spring-core", "UNKNOWN scanner null null",
                "left-pad", "1.3.0 scanner null null"));
    }

    @Test
    @DisplayName("two completions of one scan wait for each other, and the build's components are added once")
    void serialised() throws Exception {
        BuildSbomEntity sbom = new BuildSbomEntity();
        sbom.setSourceId(1L);
        sbom.setSourceSlug("ledger-ci");
        sbom.setRepoId(repository);
        sbom.setSpecVersion("1.6");
        sbom.setComponentsCount(BUILT.size());
        sbom.setDocumentSha256("c".repeat(64));
        sbom.setImportedAt(Instant.now());
        sbom.setImportedBy("pipeline");
        sbom.setApiKeyId(UUID.randomUUID());
        long importId = imports.save(sbom).getId();
        for (BuildSbom.Component component : BUILT) {
            BuildSbomComponentEntity row = new BuildSbomComponentEntity();
            row.setImportId(importId);
            row.setName(component.name());
            row.setVersion(component.version());
            row.setPurl(component.purl());
            row.setType(component.type());
            row.setLicense(component.license());
            listed.save(row);
        }

        CountDownLatch written = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Optional<Long>> first = pool.submit(() -> new TransactionTemplate(transactions).execute(status -> {
                Optional<Long> completed = builds.completeNewest(repository);
                written.countDown();
                await(release);
                return completed;
            }));
            assertThat(written.await(1, TimeUnit.MINUTES)).as("the first completion wrote").isTrue();

            Future<Optional<Long>> second = pool.submit(() -> builds.completeNewest(repository));
            awaitALockWait(second);
            release.countDown();

            assertThat(first.get(1, TimeUnit.MINUTES)).contains(scan);
            assertThat(second.get(1, TimeUnit.MINUTES)).contains(scan);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
        assertThat(components.findByScanId(scan)).extracting(ComponentEntity::getName)
                .containsExactlyInAnyOrder("spring-core", "left-pad", "spring-jcl");
    }

    /** Until the engine reports a session waiting on a lock — the second completion blocked on the first's rows. */
    private static void awaitALockWait(Future<?> second) throws Exception {
        String waiting = switch (ENGINE) {
            case POSTGRES -> "select count(*) from pg_stat_activity where wait_event_type = 'Lock'";
            case MYSQL -> "select count(*) from performance_schema.data_lock_waits";
        };
        long deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(1);
        // As root on MySQL: the lock tables answer only a session with the privileges to read them.
        String user = ENGINE == Engine.MYSQL ? "root" : CONTAINER.getUsername();
        try (Connection connection = DriverManager.getConnection(CONTAINER.getJdbcUrl(), user, CONTAINER.getPassword());
                Statement statement = connection.createStatement()) {
            while (System.nanoTime() < deadline) {
                try (ResultSet count = statement.executeQuery(waiting)) {
                    if (count.next() && count.getLong(1) > 0) {
                        return;
                    }
                }
                if (second.isDone()) {
                    throw new AssertionError("the second completion ended without ever waiting on the first");
                }
                Thread.sleep(20);
            }
        }
        throw new AssertionError("the second completion never waited on the first one's rows");
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(1, TimeUnit.MINUTES)) {
                throw new IllegalStateException("never released");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }
}
