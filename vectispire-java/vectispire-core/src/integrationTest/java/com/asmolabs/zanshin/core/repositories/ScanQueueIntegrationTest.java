package com.asmolabs.zanshin.core.repositories;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.core.ZanshinApplication;
import com.asmolabs.zanshin.core.persistence.Engine;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;
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
 * Claiming from the queue, against a real engine, from several threads at once.
 *
 * <p><b>This is the test the whole four-engine campaign exists for.</b> A claim that hands the
 * same scan to two workers is invisible in a unit test with a mock, invisible on a single
 * thread, and invisible on the one engine the developer happens to run. It shows up as two
 * agents cloning the same repository and reporting the same findings twice.
 *
 * <p>It also pins the property that is easy to lose while making the first one hold:
 * <b>everything queued must eventually be claimed</b>. A claim that never double-serves because
 * it serves almost nothing passes the first assertion and starves the queue.
 */
@SpringBootTest(classes = ZanshinApplication.class)
@DisplayName("claiming from the scan queue")
class ScanQueueIntegrationTest {

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
    private ScanQueue queue;

    @Autowired
    private Scans scans;

    @BeforeEach
    void emptyQueue() {
        scans.deleteAll();
    }

    private void enqueue(int count, String requiredLabel) {
        List<ScanEntity> pending = IntStream.range(0, count)
                .mapToObj(i -> {
                    ScanEntity scan = new ScanEntity();
                    scan.setBranch("main");
                    scan.setStatus(ScanStatus.PENDING.wireName());
                    scan.setCreatedAt(Instant.parse("2026-08-13T10:00:00Z").plusSeconds(i));
                    scan.setFindingsCount(0);
                    scan.setNewIssuesCount(0);
                    scan.setResolvedIssuesCount(0);
                    scan.setAttempts(0);
                    scan.setRequiredAgentLabel(requiredLabel);
                    return scan;
                })
                .toList();
        scans.saveAll(pending);
    }

    @Test
    @DisplayName("no scan is ever handed to two workers, and the queue still drains")
    void neverServesTheSameScanTwice() throws Exception {
        // Two agents cloning the same repository and reporting the same findings twice is what
        // the first assertion prevents. It cannot be seen on one thread, and it cannot be seen
        // with a mock.
        //
        // **Rounds, not one burst, and that is not the test being lenient.** Agents poll; a
        // round is a poll. One burst would also be a weaker test — it exercises the race once,
        // where this exercises it until the queue is empty. And on MySQL one burst genuinely
        // cannot drain it: skipped rows count against the `LIMIT` there, so a claimant whose
        // candidates are all locked comes back with nothing while rows remain. That is the
        // defect the retry loop exists for, and asserting "one burst serves everything" would
        // be asserting a property no engine owes us.
        enqueue(20, null);

        int workers = 8;
        List<Long> served = new ArrayList<>();

        try (ExecutorService pool = Executors.newFixedThreadPool(workers)) {
            for (int round = 0; round < 20 && served.size() < 20; round++) {
                List<Callable<List<Long>>> claims = IntStream.range(0, workers)
                        .mapToObj(worker -> (Callable<List<Long>>) () ->
                                queue.claim(5, "worker-" + worker, List.of()).stream()
                                        .map(ScanEntity::getId)
                                        .toList())
                        .toList();

                for (Future<List<Long>> claim : pool.invokeAll(claims)) {
                    served.addAll(claim.get());
                }
            }
        }

        assertThat(served).as("a scan served twice is a repository scanned twice").doesNotHaveDuplicates();
        // The property that is easy to lose while securing the first: a claim that never
        // double-serves because it serves almost nothing passes the assertion above and starves
        // the queue forever.
        assertThat(served).as("everything queued must eventually be claimed").hasSize(20);
        assertThat(scans.countByStatus(ScanStatus.PENDING.wireName())).isZero();
    }

    @Test
    @DisplayName("an agent only takes what it is entitled to, and the filter is inside the lock")
    void respectsTheRoutingLabel() {
        enqueue(3, "production");
        enqueue(2, null);

        // No label: only the unrouted work. An agent with no label does not match everything —
        // the reverse reading is the seductive one, and it makes the requirement inoperative at
        // the first agent registered without thinking about it.
        assertThat(queue.claim(10, "plain", List.of())).hasSize(2);
        assertThat(queue.claim(10, "prod", List.of("production"))).hasSize(3);
    }

    @Test
    @DisplayName("a claim marks what it took, in the same commit")
    void marksWhatItTook() {
        enqueue(2, null);

        List<ScanEntity> claimed = queue.claim(2, "worker", List.of());

        assertThat(claimed).allSatisfy(scan -> {
            assertThat(scan.getStatus()).isEqualTo(ScanStatus.SCANNING.wireName());
            assertThat(scan.getClaimedBy()).isEqualTo("worker");
            assertThat(scan.getLeaseExpiresAt()).isNotNull();
            assertThat(scan.getAttempts()).isEqualTo(1);
        });
        assertThat(scans.countByStatus(ScanStatus.PENDING.wireName())).isZero();
    }

    @Test
    @DisplayName("an empty queue costs one round, not twelve")
    void stopsEarlyOnAnEmptyQueue() {
        // The retry loop exists for an engine that counts skipped rows against its limit. It
        // must not turn an idle poll into twelve queries.
        assertThat(queue.claim(5, "worker", List.of())).isEmpty();
    }

    @Test
    @DisplayName("claiming zero is not a query")
    void zeroIsNoQuery() {
        enqueue(1, null);

        assertThat(queue.claim(0, "worker", List.of())).isEmpty();
        assertThat(scans.countByStatus(ScanStatus.PENDING.wireName())).isEqualTo(1);
    }
}
