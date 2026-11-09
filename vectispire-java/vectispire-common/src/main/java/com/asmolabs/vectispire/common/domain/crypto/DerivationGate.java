package com.asmolabs.vectispire.common.domain.crypto;

import java.time.Duration;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * How many password derivations run at once, and how long one waits for its turn.
 *
 * <p><b>Each Argon2id derivation holds 19 MiB for its length, and nothing bounded how many ran
 * together.</b> The sign-in throttles count per address and per account: they bound what one client
 * may try, not what every client together costs. An anonymous sign-in is admitted, and a name nobody
 * holds is verified against the stand-in hash all the same (that is what keeps the answer's timing
 * silent on whether the account exists) — so enough addresses, each within its own ceiling, ran
 * enough derivations at once to exhaust the heap of a pod sized for normal use. A derivation past
 * the bound waits a short while for a permit, then is refused as {@link DerivationsSaturated}: an
 * answer the caller can retry, rather than a process that dies for everybody.
 *
 * <p><b>The wait is fair</b>: permits go in the order they were asked for, so a stream of new
 * attempts does not starve one that has been waiting.
 */
public final class DerivationGate {

    /**
     * Two seconds: at the shipped cost a derivation takes a few tens of milliseconds, so a burst of
     * people signing in at nine o'clock clears well inside it, and a refusal still comes back before a
     * browser's patience does.
     */
    public static final Duration DEFAULT_WAIT = Duration.ofSeconds(2);

    /**
     * No more of the heap than this share goes to derivations in flight, whatever the processor count
     * says: a container without a CPU limit reports the host's, and 64 permits at 19 MiB is more than
     * the 1.5 GiB heap of the shipped Helm chart.
     */
    static final int HEAP_SHARE_DIVISOR = 4;

    private final Semaphore permits;
    private final int size;
    private final Duration wait;

    /**
     * @param permits derivations at once; zero or negative reads as {@link #defaultPermits}, as every
     *     ceiling here reads an unset value as the shipped one rather than as "nobody signs in"
     * @param wait how long a derivation waits for a permit; null, zero or negative reads as
     *     {@link #DEFAULT_WAIT}
     */
    public DerivationGate(int permits, Duration wait) {
        this.size = permits > 0 ? permits : defaultPermits();
        this.wait = wait == null || wait.isZero() || wait.isNegative() ? DEFAULT_WAIT : wait;
        this.permits = new Semaphore(this.size, true);
    }

    /** The shipped bound: one per processor, at least two, and no more than a quarter of the heap holds. */
    public static int defaultPermits() {
        return defaultPermits(Runtime.getRuntime().availableProcessors(), Runtime.getRuntime().maxMemory());
    }

    static int defaultPermits(int processors, long maxHeapBytes) {
        // Argon2 at parallelism 1 keeps one processor busy; more permits than processors only queue
        // inside the scheduler instead of at the gate, holding their memory while they do.
        long byProcessors = Math.max(2, processors);
        long byHeap = Math.max(1, maxHeapBytes / HEAP_SHARE_DIVISOR / PasswordHasher.derivationBytes());
        return (int) Math.min(byProcessors, byHeap);
    }

    /** How many derivations may run at once. */
    public int permits() {
        return size;
    }

    /** How long a derivation waits for its turn before it is refused. */
    public Duration await() {
        return wait;
    }

    /**
     * What a refused caller is told to wait: the gate's own wait, at least a second. Saturation is
     * measured in derivations, which last milliseconds, so the condition clears in about that time.
     */
    public Duration retryAfter() {
        return wait.compareTo(Duration.ofSeconds(1)) < 0 ? Duration.ofSeconds(1) : wait;
    }

    /**
     * Runs one derivation under a permit, released however it ends.
     *
     * @throws DerivationsSaturated when no permit came within the wait
     */
    public <T> T run(Supplier<T> derivation) {
        boolean acquired;
        try {
            acquired = permits.tryAcquire(wait.toNanos(), TimeUnit.NANOSECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new DerivationsSaturated(retryAfter());
        }
        if (!acquired) {
            throw new DerivationsSaturated(retryAfter());
        }
        try {
            return derivation.get();
        } finally {
            permits.release();
        }
    }

    /** Permits free right now — for a test to see that a refused or failed derivation gave its back. */
    public int available() {
        return permits.availablePermits();
    }
}
