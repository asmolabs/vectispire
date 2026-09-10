package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The worker tick hands its round to a thread of its own.
 *
 * <p><b>Why this exists.</b> A round executes the scans it claims, in this process, one after
 * another. It used to do that on the caller's thread — the scheduler's, and the scheduler had
 * one thread for everything: the outbox relay, the scan scheduler, the hourly maintenance, and
 * the re-check that answers a remote agent's long poll. So a single local scan, minutes long,
 * stopped all four. The built-in worker starved the very fleet the remote agent exists to be.
 *
 * <p>Nothing could see it: every assertion about the worker was about what a round <em>does</em>,
 * and a round does the same thing on either thread. What separates the two designs is whether
 * {@code tick()} returns while the round is still running — so that is what is asserted here,
 * with a dispatch that does not return until this test lets it.
 */
@DisplayName("the worker tick")
class ScanWorkerOffloadTest {

    /** Generous: the assertion is "immediately" against "the length of a scan", not a benchmark. */
    private static final Duration RETURNS_WITHIN = Duration.ofSeconds(2);

    @Test
    @DisplayName("returns while the round is still running")
    void returns_while_the_round_is_still_running() throws Exception {
        CountDownLatch dispatchStarted = new CountDownLatch(1);
        CountDownLatch releaseDispatch = new CountDownLatch(1);
        AtomicReference<String> dispatchThread = new AtomicReference<>();

        ScanDispatcher dispatcher = mock(ScanDispatcher.class);
        when(dispatcher.dispatch(anyString(), anyInt(), anyList())).thenAnswer(invocation -> {
            dispatchThread.set(Thread.currentThread().getName());
            dispatchStarted.countDown();
            releaseDispatch.await(10, TimeUnit.SECONDS);
            return ScanDispatcher.Dispatched.NOTHING;
        });

        ScanWorker worker = new ScanWorker(dispatcher, new WorkerProperties(true, 2, ""));
        try {
            long before = System.nanoTime();
            worker.tick();
            Duration took = Duration.ofNanos(System.nanoTime() - before);

            assertThat(dispatchStarted.await(10, TimeUnit.SECONDS))
                    .as("the round must actually start")
                    .isTrue();

            // The whole point. Before the fix this line measured the length of the scan, because
            // `tick()` did not return until `dispatch` did.
            assertThat(took)
                    .as("tick must not wait for the round it submitted")
                    .isLessThan(RETURNS_WITHIN);

            assertThat(dispatchThread.get())
                    .as("and the round runs on the worker's own thread, not the scheduler's")
                    .isEqualTo("vectispire-scan-worker");

            // The guard still means what it meant: a tick arriving mid-round is skipped, so
            // rounds never overlap however short the period is.
            worker.tick();
            worker.tick();
        } finally {
            releaseDispatch.countDown();
        }
    }

    @Test
    @DisplayName("accepts the next round once the previous one has finished")
    void accepts_the_next_round_once_the_previous_one_has_finished() throws Exception {
        CountDownLatch rounds = new CountDownLatch(2);

        ScanDispatcher dispatcher = mock(ScanDispatcher.class);
        when(dispatcher.dispatch(anyString(), anyInt(), anyList())).thenAnswer(invocation -> {
            rounds.countDown();
            return ScanDispatcher.Dispatched.NOTHING;
        });

        ScanWorker worker = new ScanWorker(dispatcher, new WorkerProperties(true, 2, ""));
        worker.tick();
        // Until the first round releases the guard the second is skipped, so this has to wait for
        // it rather than fire straight away — the busy flag is released on the worker's thread.
        for (int attempt = 0; attempt < 100 && rounds.getCount() > 1; attempt++) {
            Thread.sleep(10);
        }
        worker.tick();

        assertThat(rounds.await(10, TimeUnit.SECONDS))
                .as("both rounds ran")
                .isTrue();
    }

    @Test
    @DisplayName("does nothing at all when the built-in worker is switched off")
    void does_nothing_at_all_when_the_worker_is_switched_off() {
        ScanDispatcher dispatcher = mock(ScanDispatcher.class);
        ScanWorker worker = new ScanWorker(dispatcher, new WorkerProperties(false, 2, ""));

        worker.tick();

        org.mockito.Mockito.verifyNoInteractions(dispatcher);
    }
}
