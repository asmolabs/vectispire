package com.asmolabs.vectispire.core.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.owasp.CoverageWeek;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyCoverageService.Outcome;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageEntity;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
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
 * Two instances capturing the same week, on a real engine.
 *
 * <p><b>What is in question.</b> No instance is elected for the maintenance turn, so two control planes
 * behind one load balancer can both find the current week due and both write it. The unique key on
 * (week, target, category) is the arbiter; this suite asks whether the arbitration ends in one complete
 * set — never a duplicate, never two captures mixed — and whether the loser says so in words rather than
 * as a failure, which would log a warning every six hours on every instance but one.
 *
 * <p><b>The interleaving is forced, not hoped for.</b> The first writer's transaction is held open with
 * its rows inserted; the second capture runs in full — the gate outside the write, the reading, the gate
 * again inside it, the delete, the inserts — until the engine itself reports it waiting on a lock. Only
 * then is the first released. Launching two captures at once would meet in the write a few runs in a
 * hundred, and pass the others without having tested anything.
 *
 * <p><b>The engines arbitrate differently, and each is asserted as it does.</b> On PostgreSQL the second
 * one's delete sees nothing it may delete, its insert waits on the first one's key, and once the first
 * commits it is refused: the week holds the first capture, and the second reports it was taken elsewhere.
 * On MySQL the second one's delete is a locking read: it waits on the first one's rows, then takes them,
 * and its own set is the one kept.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the weekly OWASP record under two instances, on a real engine")
class OwaspWeeklyCoverageConcurrencyIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    private static final Instant FIRST = Instant.parse("2026-09-30T10:00:00Z");
    private static final Instant SECOND = FIRST.plus(Duration.ofMinutes(1));
    private static final Instant WEEK = CoverageWeek.startOf(FIRST);
    private static final int TARGETS = 3;

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
    private OwaspWeeklyCoverageService weekly;

    @Autowired
    private OwaspWeeklyCoverageRepository rows;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private PlatformTransactionManager transactions;

    @BeforeEach
    void anEstate() {
        rows.deleteAll();
        repositories.deleteAll();
        containers.deleteAll();
        for (int i = 0; i < TARGETS - 1; i++) {
            RepositoryEntity repository = new RepositoryEntity();
            repository.setUrl("ssh://git@example.com/team/weekly-" + i + ".git");
            repository.setName("weekly-" + i);
            repository.setBranch("main");
            repositories.save(repository);
        }
        ContainerEntity image = new ContainerEntity();
        image.setImageName("registry.example.invalid/weekly");
        image.setTag("1.0.0");
        containers.save(image);
    }

    @Test
    @DisplayName("an empty week written by two at once: one complete capture, and the loser says why")
    void anEmptyWeek() throws Exception {
        Outcome second = race();

        assertSettled(second);
    }

    @Test
    @DisplayName("a week already captured, rewritten by two at once: the same")
    void aWeekAlreadyCaptured() throws Exception {
        // Both pass the gate on rows seven hours old; on PostgreSQL the second one's delete now waits on
        // rows the first one deletes, rather than on its key.
        assertThat(weekly.capture(FIRST.minus(Duration.ofHours(7)))).isEqualTo(Outcome.CAPTURED);

        Outcome second = race();

        assertSettled(second);
    }

    /**
     * The first writer holds its transaction with its rows written; the second capture runs until the
     * engine reports a lock wait; then the first commits.
     *
     * @return the second capture's outcome
     */
    private Outcome race() throws Exception {
        List<OwaspWeeklyCoverageEntity> firsts = weekly.read(WEEK, FIRST);
        CountDownLatch written = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = pool.submit(() -> new TransactionTemplate(transactions).execute(status -> {
                boolean wrote = weekly.write(WEEK, FIRST, firsts);
                written.countDown();
                await(release);
                return wrote;
            }));
            assertThat(written.await(1, TimeUnit.MINUTES)).as("the first writer wrote").isTrue();

            Future<Outcome> second = pool.submit(() -> weekly.capture(SECOND));
            awaitALockWait(second);
            release.countDown();

            assertThat(first.get(1, TimeUnit.MINUTES)).as("the first writer found the week due").isTrue();
            return second.get(1, TimeUnit.MINUTES);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    private void assertSettled(Outcome second) {
        List<OwaspWeeklyCoverageEntity> week = rows.findByWeekStart(WEEK);
        assertThat(week).as("one row per target and category: no duplicate, nothing lost").hasSize(TARGETS * 10);
        assertThat(week.stream()
                        .map(row -> row.getTargetKind() + ":" + row.getTargetId() + ":" + row.getCategory())
                        .collect(Collectors.toSet()))
                .hasSize(TARGETS * 10);
        assertThat(week.stream().map(OwaspWeeklyCoverageEntity::getCapturedAt).collect(Collectors.toSet()))
                .as("one capture's set, never two mixed")
                .hasSize(1);

        switch (ENGINE) {
            case POSTGRES -> {
                assertThat(second)
                        .as("refused on the key, and read against the committed week as the race it was — not a failure")
                        .isEqualTo(Outcome.TAKEN_ELSEWHERE);
                assertThat(week.getFirst().getCapturedAt()).isEqualTo(FIRST);
            }
            case MYSQL -> {
                assertThat(second).as("its delete waited for the first one's rows, then took them").isEqualTo(Outcome.CAPTURED);
                assertThat(week.getFirst().getCapturedAt()).isEqualTo(SECOND);
            }
        }
    }

    /**
     * Until the engine reports a session waiting on a lock — the second capture blocked on the first —
     * or the second capture ended without blocking, which the outcome then has to explain.
     */
    private static void awaitALockWait(Future<Outcome> second) throws Exception {
        String waiting = switch (ENGINE) {
            case POSTGRES -> "select count(*) from pg_stat_activity where wait_event_type = 'Lock'";
            // Not `information_schema.innodb_trx`: on the pinned MySQL 9.4 it went on listing the waiting
            // transaction as RUNNING, or not at all, while `data_lock_waits` counted its wait.
            case MYSQL -> "select count(*) from performance_schema.data_lock_waits";
        };
        long deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(1);
        // As root on MySQL: the lock tables answer only a session with the privileges to read them, which
        // the container's user lacks; the container gives root the same password.
        String user = ENGINE == Engine.MYSQL ? "root" : CONTAINER.getUsername();
        try (Connection connection = DriverManager.getConnection(CONTAINER.getJdbcUrl(), user, CONTAINER.getPassword());
                Statement statement = connection.createStatement()) {
            while (System.nanoTime() < deadline) {
                try (ResultSet count = statement.executeQuery(waiting)) {
                    if (count.next() && count.getLong(1) > 0) {
                        return;
                    }
                }
                assertThat(second.isDone())
                        .as("the second capture ended without ever waiting on the first: %s", second.isDone() ? second.get() : null)
                        .isFalse();
                Thread.sleep(20);
            }
        }
        throw new AssertionError("the second capture never waited on the first one's lock");
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
