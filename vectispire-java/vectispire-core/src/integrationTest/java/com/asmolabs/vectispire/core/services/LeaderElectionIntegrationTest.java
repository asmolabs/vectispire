package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.repositories.LeaderLeases;
import java.time.Duration;
import java.time.Instant;
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
 * The leader lease, against a real engine, contended.
 *
 * <p><b>Two leaders is the failure this exists to prevent</b>, and it is invisible everywhere
 * else: a unit test with a mock cannot race, a single thread cannot collide, and the symptom in
 * production is not an error but every target scanned twice a night — which reads as a busy
 * fleet rather than as a bug.
 *
 * <p>The conditional update is the whole mechanism. Whether "exactly one row changed" really
 * holds under concurrency is a property of the engine, not of the Java, which is why this runs
 * on all four.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the leader lease under contention")
class LeaderElectionIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    private static final String JOB = "scheduler";
    private static final int CLAIMANTS = 8;

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
    private LeaderElection election;

    @Autowired
    private LeaderLeases leases;

    @BeforeEach
    void clearTheLease() {
        leases.deleteAll();
    }

    @Test
    @DisplayName("eight instances start together and exactly one wins")
    void onlyOneWinsTheFirstAcquisition() throws Exception {
        Instant at = Instant.now();

        // The first acquisition is an insert, and the primary key is what arbitrates. Every loser
        // has to catch its violation and answer "no" rather than propagate it.
        assertThat(winners(at)).isEqualTo(1);
        assertThat(leases.findAll()).hasSize(1);
    }

    @Test
    @DisplayName("the holder renews, and nobody takes it from under them")
    void aLiveLeaseIsNotStolen() throws Exception {
        Instant at = Instant.now();
        assertThat(election.acquire(JOB, "holder", at)).isTrue();

        // A live lease belongs to its holder. Renewal is what keeps a leader stable — one that
        // had to win again every tick would move the work around the fleet for no reason.
        assertThat(election.acquire(JOB, "holder", at.plusSeconds(1))).isTrue();
        assertThat(winners(at.plusSeconds(2))).isZero();
        assertThat(election.currentHolder(JOB, at.plusSeconds(2))).contains("holder");
    }

    @Test
    @DisplayName("once it lapses, exactly one of eight takes it over")
    void exactlyOneTakesOverAnExpiredLease() throws Exception {
        Instant at = Instant.now();
        assertThat(election.acquire(JOB, "the-dead-one", at)).isTrue();

        // Past the lease. Eight instances see it expired at the same moment; the conditional
        // update carries what each of them read, so seven of them change no row.
        Instant afterExpiry = at.plus(Duration.ofHours(1));
        assertThat(winners(afterExpiry)).isEqualTo(1);
        assertThat(election.currentHolder(JOB, afterExpiry)).isPresent().get().isNotEqualTo("the-dead-one");
    }

    @Test
    @DisplayName("a released lease is available at once, and to one taker")
    void releasingHandsItOverImmediately() throws Exception {
        Instant at = Instant.now();
        election.acquire(JOB, "holder", at);

        assertThat(election.release(JOB, "holder")).isTrue();
        // Released rather than expired: a successor takes it now instead of waiting out the
        // lease, and still only one does.
        assertThat(winners(at.plusSeconds(1))).isEqualTo(1);
    }

    @Test
    @DisplayName("releasing a lease that is not yours changes nothing")
    void releasingSomebodyElsesLeaseIsRefused() {
        Instant at = Instant.now();
        election.acquire(JOB, "holder", at);

        assertThat(election.release(JOB, "an-impostor")).isFalse();
        assertThat(election.currentHolder(JOB, at.plusSeconds(1))).contains("holder");
    }

    /** How many of eight concurrent claimants came away holding the lease. */
    private long winners(Instant at) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(CLAIMANTS);
        try {
            List<Callable<Boolean>> claims = IntStream.range(0, CLAIMANTS)
                    .mapToObj(index -> (Callable<Boolean>) () -> election.acquire(JOB, "instance-" + index, at))
                    .toList();

            long held = 0;
            for (Future<Boolean> claim : pool.invokeAll(claims)) {
                if (claim.get()) {
                    held++;
                }
            }
            return held;
        } finally {
            pool.shutdownNow();
        }
    }
}
