package com.asmolabs.vectispire.core.access;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.access.persistence.RateWindowRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
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
 * The shared request counter, on a real engine, contended.
 *
 * <p>Two properties are the engine's rather than the Java's: that {@code set hits = hits + 1} loses
 * no hit when instances increment together, and that the primary key refuses a second first-hit
 * insert with an exception the service can catch — and that on PostgreSQL, where a failed statement
 * poisons its transaction, the increment that follows still commits.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("the shared request counter, on a real engine")
class RateWindowsIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();
    private static final Duration WINDOW = Duration.ofMinutes(1);
    private static final int BURST = 16;

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
    private RateWindowRepository repository;

    /** One instant for a whole test, so no test straddles a window's boundary. */
    private Clock clock;

    @BeforeEach
    void freezeTheClock() {
        clock = Clock.fixed(Instant.now(), ZoneOffset.UTC);
    }

    @Test
    @DisplayName("admits exactly the ceiling, one after another, and counts every hit")
    void admitsTheCeiling() {
        RateWindows windows = new RateWindows(repository, clock);
        String subject = subject();

        List<Boolean> admitted = new ArrayList<>();
        for (int hit = 0; hit < 7; hit++) {
            admitted.add(windows.hit(RateWindows.Limit.TICKET_WEBHOOK, subject, 5, WINDOW).admitted());
        }

        assertThat(admitted).containsExactly(true, true, true, true, true, false, false);
        assertThat(repository.hitsOf(key(subject))).contains(7);
    }

    @Test
    @DisplayName("a first hit that loses the insert to another instance is counted, not lost")
    void aLostInsertIncrementsInstead() {
        // Forced rather than hoped for: the other instance inserts the window's row between this
        // one's increment (which found no row) and its insert (which the key then refuses).
        String subject = subject();
        AtomicBoolean interleaved = new AtomicBoolean();
        RateWindowRepository racing = (RateWindowRepository) Proxy.newProxyInstance(
                RateWindowRepository.class.getClassLoader(),
                new Class<?>[] {RateWindowRepository.class},
                (proxy, method, arguments) -> {
                    try {
                        Object result = method.invoke(repository, arguments);
                        if (method.getName().equals("increment") && interleaved.compareAndSet(false, true)) {
                            assertThat(result).as("nobody had hit this window yet").isEqualTo(0);
                            repository.insertFirst(key(subject), clock.instant().plus(WINDOW));
                        }
                        return result;
                    } catch (InvocationTargetException thrown) {
                        throw thrown.getCause();
                    }
                });

        RateWindows.Outcome outcome = new RateWindows(racing, clock)
                .hit(RateWindows.Limit.TICKET_WEBHOOK, subject, 5, WINDOW);

        assertThat(interleaved).isTrue();
        assertThat(outcome.admitted()).isTrue();
        assertThat(repository.hitsOf(key(subject))).as("the other instance's hit and this one").contains(2);
    }

    @Test
    @DisplayName("sixteen instances hitting at once lose no hit, and never admit past the ceiling")
    void aBurstIsCountedWhole() throws Exception {
        RateWindows windows = new RateWindows(repository, clock);
        String subject = subject();
        int ceiling = 5;

        CountDownLatch ready = new CountDownLatch(BURST);
        CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(BURST);
        List<Future<Boolean>> hits = new ArrayList<>();
        try {
            for (int caller = 0; caller < BURST; caller++) {
                hits.add(pool.submit(() -> {
                    ready.countDown();
                    go.await();
                    return windows.hit(RateWindows.Limit.TICKET_WEBHOOK, subject, ceiling, WINDOW).admitted();
                }));
            }
            assertThat(ready.await(30, TimeUnit.SECONDS)).isTrue();
            go.countDown();
            long admitted = 0;
            for (Future<Boolean> hit : hits) {
                admitted += hit.get(60, TimeUnit.SECONDS) ? 1 : 0;
            }

            // Every hit counted — a lost update would leave fewer, and so would a failure the
            // service admitted after swallowing — and none admitted past the ceiling.
            assertThat(repository.hitsOf(key(subject))).contains(BURST);
            assertThat(admitted).isLessThanOrEqualTo(ceiling);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("the purge takes the closed windows and keeps the open one")
    void closedWindowsArePurged() {
        String subject = subject();
        new RateWindows(repository, clock).hit(RateWindows.Limit.TICKET_WEBHOOK, subject, 5, WINDOW);
        String stale = "webhook:0:" + Digests.sha256Hex(subject);
        repository.insertFirst(stale, clock.instant().minus(Duration.ofHours(1)));

        new RateWindows(repository, clock).purgeClosed();

        assertThat(repository.findById(stale)).isEmpty();
        assertThat(repository.hitsOf(key(subject))).contains(1);
    }

    private String key(String subject) {
        long number = Math.floorDiv(clock.instant().toEpochMilli(), WINDOW.toMillis());
        return "webhook:" + number + ":" + Digests.sha256Hex(subject);
    }

    private static String subject() {
        return "203.0.113." + System.nanoTime();
    }
}
