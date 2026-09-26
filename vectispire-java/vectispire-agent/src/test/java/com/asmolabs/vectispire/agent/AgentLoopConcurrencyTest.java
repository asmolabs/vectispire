package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import java.time.Duration;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Several scans at once, and never one more than the limit.
 *
 * <p><b>Latches, no sleeps.</b> A scan here is a function that blocks until the test lets it go, so
 * "three are running" is a fact the test waits for rather than a delay it hopes was long enough. The
 * one thing that cannot be observed by a latch — that the loop has <em>stopped asking</em> — is read
 * from the polling thread's state: parked in {@code WAITING} with every slot busy means it is blocked
 * on a slot, since the claim itself never blocks here.
 */
@DisplayName("a remote agent running several scans at once")
class AgentLoopConcurrencyTest {

    private static final AgentProperties PROPERTIES = new AgentProperties(
            "https://vectispire.example", "zsk-token",
            Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(60), "docker");

    private static final Duration PATIENCE = Duration.ofSeconds(10);

    private AgentProtocol protocol;
    private final AtomicLong nextScan = new AtomicLong(1);
    private final AtomicInteger running = new AtomicInteger();
    private final AtomicInteger mostAtOnce = new AtomicInteger();
    private final CountDownLatch release = new CountDownLatch(1);
    private AgentLoop loop;
    private Thread poller;

    @BeforeEach
    void wire() {
        protocol = mock(AgentProtocol.class);
        when(protocol.claim(any())).thenAnswer(call -> claimed(OptionalInt.empty()));
        when(protocol.heartbeat(anyLong())).thenReturn(true);
        when(protocol.submit(anyLong(), any())).thenReturn(true);
    }

    @AfterEach
    void stop() throws InterruptedException {
        release.countDown();
        if (loop != null) {
            loop.stop();
            loop.close();
        }
        if (poller != null) {
            poller.join(PATIENCE.toMillis());
        }
    }

    @Test
    @DisplayName("runs its limit in parallel, and does not even ask for one more")
    void runsTheLimitAndNoMore() throws Exception {
        CountDownLatch threeStarted = new CountDownLatch(3);
        start(3, threeStarted);

        assertThat(threeStarted.await(PATIENCE.toSeconds(), TimeUnit.SECONDS)).as("three scans running at once").isTrue();
        awaitParkedWithEverySlotBusy(3);

        // Parked with three running: it asked exactly three times. A fourth claim would have been
        // answered — the fake queue never runs dry — and would have started a fourth scan.
        verify(protocol, times(3)).claim(any());
        assertThat(running.get()).isEqualTo(3);
        assertThat(mostAtOnce.get()).isEqualTo(3);
    }

    @Test
    @DisplayName("a finished scan frees its slot, and each scan reports on its own")
    void aFinishedScanFreesItsSlot() throws Exception {
        CountDownLatch twoStarted = new CountDownLatch(2);
        start(2, twoStarted);
        assertThat(twoStarted.await(PATIENCE.toSeconds(), TimeUnit.SECONDS)).isTrue();
        awaitParkedWithEverySlotBusy(2);

        release.countDown();
        // Released, the scans finish one by one and the loop keeps topping up — never past two.
        awaitTrue(() -> nextScan.get() > 6);
        verify(protocol, atLeast(4)).submit(anyLong(), any());
        assertThat(mostAtOnce.get()).isEqualTo(2);
    }

    @Test
    @DisplayName("a limit raised on a claim's answer is used on the next one")
    void followsTheLimitTheControlPlaneSends() throws Exception {
        when(protocol.claim(any())).thenAnswer(call -> claimed(OptionalInt.of(2)));
        CountDownLatch twoStarted = new CountDownLatch(2);
        start(1, twoStarted);

        // Started with one, told two by the first answer: the second scan starts while the first
        // is still running.
        assertThat(twoStarted.await(PATIENCE.toSeconds(), TimeUnit.SECONDS)).isTrue();
        awaitParkedWithEverySlotBusy(2);
        assertThat(mostAtOnce.get()).isEqualTo(2);
    }

    @Test
    @DisplayName("stopping claims nothing more and waits for the running scans to be handed back")
    void stoppingWaitsForTheRunningScans() throws Exception {
        CountDownLatch twoStarted = new CountDownLatch(2);
        start(2, twoStarted);
        assertThat(twoStarted.await(PATIENCE.toSeconds(), TimeUnit.SECONDS)).isTrue();
        awaitParkedWithEverySlotBusy(2);

        loop.stop();
        // Past the loop and waiting on the two scans, rather than returning over them or
        // interrupting them: the frame is the executor's termination wait, and nothing was handed
        // back yet because nothing was cut short.
        awaitTrue(() -> java.util.Arrays.stream(poller.getStackTrace())
                .anyMatch(frame -> frame.getMethodName().equals("awaitTermination")));
        assertThat(poller.isAlive()).isTrue();
        assertThat(running.get()).isEqualTo(2);
        verify(protocol, times(0)).submit(anyLong(), any());

        release.countDown();
        poller.join(PATIENCE.toMillis());
        assertThat(poller.isAlive()).as("serve returns once both are handed back").isFalse();
        verify(protocol, times(2)).submit(anyLong(), any());
        verify(protocol, times(2)).claim(any());
    }

    /** Starts the loop on a thread of its own; each scan counts itself and waits for the release. */
    private void start(int limit, CountDownLatch started) {
        loop = new AgentLoop(protocol, task -> {
            int now = running.incrementAndGet();
            mostAtOnce.accumulateAndGet(now, Math::max);
            started.countDown();
            try {
                release.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } finally {
                running.decrementAndGet();
            }
            return ScanArtifacts.builder().build(Duration.ofSeconds(1));
        }, PROPERTIES, limit);
        poller = new Thread(loop::serve, "agent-loop-under-test");
        poller.start();
    }

    private AgentProtocol.Claim claimed(OptionalInt limit) {
        return new AgentProtocol.Claim(
                Optional.of(new AgentProtocol.AssignedTask(
                        nextScan.getAndIncrement(),
                        new ScanTask(
                                new ScanTask.Target.Repository("git@example.invalid:team/service.git", "main", "", null),
                                null,
                                Set.of(ScanTask.Step.DEPENDENCIES)))),
                limit);
    }

    private void awaitParkedWithEverySlotBusy(int busy) {
        awaitTrue(() -> running.get() == busy && poller.getState() == Thread.State.WAITING);
    }

    /** Spins, bounded — the condition is expected within microseconds, never after a delay. */
    private static void awaitTrue(BooleanSupplier condition) {
        long deadline = System.nanoTime() + PATIENCE.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("condition not reached within " + PATIENCE);
            }
            Thread.onSpinWait();
        }
    }
}
