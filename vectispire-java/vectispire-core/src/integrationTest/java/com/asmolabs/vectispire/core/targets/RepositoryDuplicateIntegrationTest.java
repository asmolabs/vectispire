package com.asmolabs.vectispire.core.targets;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.targets.RepositoryAdministrationService.Changes;
import com.asmolabs.vectispire.core.targets.RepositoryAdministrationService.TargetAlreadyRegisteredException;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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
 * Two administrators filing the same repository at the same moment, on a real engine.
 *
 * <p><b>What is in question.</b> The service checks for a twin before it writes, and two creations can
 * both pass that check before either commits. The unique index on {@code identity_guard} (V74) is the
 * arbiter; this asks whether exactly one row results, and whether the loser is answered the same 409 a
 * creation a second later would get — not a 500 carrying the driver's message.
 *
 * <p><b>The interleaving is forced.</b> The first creation runs inside a transaction held open after
 * its insert; the second, spelled another way (SSH against HTTPS), runs its check — which cannot see an
 * uncommitted row — and its insert, until the engine reports it waiting on the first one's key. Only then
 * is the first released. Two creations launched together would meet in the write a few runs in a
 * hundred, and pass the others without having tested the index.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("one repository target filed twice, on a real engine")
class RepositoryDuplicateIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();
    private static final RequestActor ACTOR = new RequestActor("race-test", null, null);

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
    private RepositoryAdministrationService inventory;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private PlatformTransactionManager transactions;

    @Autowired
    private RepositoryIdentityService identities;

    @BeforeEach
    void noRepository() {
        repositories.deleteAll();
    }

    @Test
    @DisplayName("one is filed, the other is refused as the twin it is")
    void oneWinsTheOtherIsTold() throws Exception {
        CountDownLatch written = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<RepositoryView> first = pool.submit(() -> new TransactionTemplate(transactions).execute(status -> {
                RepositoryView filed = inventory.create(
                        changes("https://gitlab.example.org/team/raced.git"), Visibility.everything(), ACTOR);
                written.countDown();
                await(release);
                return filed;
            }));
            assertThat(written.await(1, TimeUnit.MINUTES)).as("the first creation wrote its row").isTrue();

            Future<RepositoryView> second = pool.submit(() -> inventory.create(
                    changes("git@gitlab.example.org:Team/Raced"), Visibility.everything(), ACTOR));
            awaitALockWait(second);
            release.countDown();

            long winner = first.get(1, TimeUnit.MINUTES).id();
            assertThat(second)
                    .failsWithin(1, TimeUnit.MINUTES)
                    .withThrowableOfType(ExecutionException.class)
                    .havingCause()
                    .isInstanceOfSatisfying(TargetAlreadyRegisteredException.class, refused ->
                            assertThat(refused.members()).containsEntry("existingRepositoryId", winner));
            assertThat(repositories.findAll()).as("one row, the first one's")
                    .extracting(RepositoryEntity::getId)
                    .containsExactly(winner);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("targets filed twice before the rule: the engine keeps both, the oldest takes the guard")
    void twinsFoundByTheUpgrade() {
        // Three rows without a guard: nulls are distinct in a unique index on both engines, or V74 could
        // not have been applied to an installation holding a twin.
        long older = legacyRow("https://gitlab.example.org/team/legacy.git");
        long younger = legacyRow("git@gitlab.example.org:team/legacy.git");
        long third = legacyRow("ssh://git@gitlab.example.org/team/legacy");

        assertThat(identities.keyUnkeyed()).isEqualTo(new RepositoryIdentityService.Keyed(1, 2));

        assertThat(repositories.findById(older).orElseThrow().getIdentityGuard()).isNotNull();
        assertThat(repositories.findById(younger).orElseThrow().getIdentityGuard()).isNull();
        assertThat(repositories.findById(third).orElseThrow().getIdentityGuard()).isNull();
        assertThat(repositories.findAll()).extracting(RepositoryEntity::getUrlIdentity)
                .containsOnly("gitlab.example.org/team/legacy");
    }

    private long legacyRow(String url) {
        RepositoryEntity row = new RepositoryEntity();
        row.setUrl(url);
        row.setBranch("main");
        return repositories.save(row).getId();
    }

    private static Changes changes(String url) {
        return new Changes(url, "main", null, null, null, null, null, null, null);
    }

    /** Until the engine reports a session waiting on a lock — the second insert blocked on the first one's key. */
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
                    throw new AssertionError("the second creation ended without ever waiting on the first: "
                            + outcome(second));
                }
                Thread.sleep(20);
            }
        }
        throw new AssertionError("the second creation never waited on the first one's key");
    }

    private static String outcome(Future<?> done) {
        try {
            return "filed " + done.get();
        } catch (Exception failed) {
            return "failed " + failed.getCause();
        }
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
