package com.asmolabs.vectispire.core.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.audit.internal.AuditMirror;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditChainHeadRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
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
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The audit chain under concurrent writers, on a real engine.
 *
 * <p><b>What is in question.</b> An entry reads the chain's head and inserts itself onto it, in a short
 * transaction of its own; the read takes no lock and nothing makes {@code previous_hash} unique. Two
 * writers that read the same head before either commits would both chain onto it, and the
 * verification — which follows the chain in timestamp order — would then report a break in a log
 * nobody touched: an "audit chain broken" alarm, a SIEM event, for nothing. Every audit test until this
 * one wrote from a single thread, so none could say whether that happens. Asked before decision 0033's
 * fourth lot, which would have lengthened the window by writing an entry inside a scan's transaction.
 *
 * <p>Two shapes: many threads of one instance, and two instances — two services over the same table,
 * each with its own monotonic clock, as two control planes behind one load balancer.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the audit chain under concurrent writers, on a real engine")
class AuditChainConcurrencyIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    private static final int THREADS = 8;
    private static final int ENTRIES_EACH = 25;

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
    private AuditLogService audit;

    @Autowired
    private AuditLogRepository entries;

    @Autowired
    private AuditChainHeadRepository heads;

    @Autowired
    private PlatformTransactionManager transactions;

    @Autowired
    private Clock clock;

    @BeforeEach
    void empty() {
        entries.deleteAll();
    }

    @Test
    @DisplayName("many threads of one instance: every entry kept, each chained onto its own predecessor, and the chain verifies")
    void oneInstance() throws Exception {
        writeConcurrently(thread -> audit);

        assertIntact();
    }

    @Test
    @DisplayName("two instances over one table, one clock 50 ms behind: every entry kept, chained in order, and the chain verifies")
    void twoInstances() throws Exception {
        // Behind, as a second machine's clock is: the lock orders the writers, not their clocks, and an
        // entry dated before the head it chains onto is read out of order by the verification.
        AuditLogService other = new AuditLogService(entries, heads, new AuditMirror.Disabled(),
                Clock.offset(clock, Duration.ofMillis(-50)), List.of(), transactions);

        writeConcurrently(thread -> thread % 2 == 0 ? audit : other);

        assertIntact();
    }

    /** Every thread released at once by a latch, so that the reads of the head meet. */
    private void writeConcurrently(Function<Integer, AuditLogService> writerOf) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> done = new ArrayList<>();
        try {
            for (int thread = 0; thread < THREADS; thread++) {
                int t = thread;
                AuditLogService writer = writerOf.apply(t);
                done.add(pool.submit(() -> {
                    go.await();
                    for (int i = 0; i < ENTRIES_EACH; i++) {
                        writer.record(AuditLogService.Record.of(
                                AuditOperation.SETTING_UPDATED, "thread-" + t, "entry " + i, "writer-" + t));
                    }
                    return null;
                }));
            }
            go.countDown();
            for (Future<?> each : done) {
                each.get(2, TimeUnit.MINUTES);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private void assertIntact() {
        List<AuditLogEntity> all = entries.findAllByOrderByTimestampAscIdAsc();
        assertThat(all).as("no entry lost: record() logs and drops what it cannot write").hasSize(THREADS * ENTRIES_EACH);

        Map<String, Long> successors = all.stream()
                .filter(entry -> entry.getPreviousHash() != null)
                .collect(Collectors.groupingBy(AuditLogEntity::getPreviousHash, Collectors.counting()));
        assertThat(successors.entrySet().stream().filter(link -> link.getValue() > 1).map(Map.Entry::getKey).toList())
                .as("no two entries chained onto the same predecessor — a fork")
                .isEmpty();

        assertThat(audit.verify()).returns(null, AuditChain.Verification::broken);
    }
}
