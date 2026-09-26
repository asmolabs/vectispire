package com.asmolabs.vectispire.agent;

import com.asmolabs.vectispire.common.domain.agents.AgentConcurrency;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * How many scans this agent may still start: a semaphore whose size the control plane changes.
 *
 * <p><b>Not {@link java.util.concurrent.Semaphore}</b>, because the limit moves while scans run.
 * Lowering a semaphore means taking permits back, which blocks until running scans release them —
 * or, with {@code reducePermits}, drives the count negative in a way nothing reads. Here the limit
 * is a number and the scans in progress are another; a lowered limit simply stops new starts until
 * enough of the running ones have finished, which is exactly what the control plane does too.
 *
 * <p><b>Closing wakes the one thread waiting</b>, so a shutdown requested while every slot is busy
 * does not wait for a scan to finish before it stops polling.
 */
final class Slots {

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    private int limit;
    private int busy;
    private boolean closed;

    Slots(int limit) {
        this.limit = AgentConcurrency.effective(limit);
    }

    /**
     * Waits for a free slot and takes it.
     *
     * @return false when the slots were closed instead: nothing was taken, and the caller stops
     */
    boolean acquire() throws InterruptedException {
        lock.lock();
        try {
            while (!closed && busy >= limit) {
                changed.await();
            }
            if (closed) {
                return false;
            }
            busy++;
            return true;
        } finally {
            lock.unlock();
        }
    }

    void release() {
        lock.lock();
        try {
            busy--;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /** A limit the control plane announced; clamped like everywhere else it is read. */
    void resize(int requested) {
        lock.lock();
        try {
            limit = AgentConcurrency.effective(requested);
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    void close() {
        lock.lock();
        try {
            closed = true;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    int limit() {
        lock.lock();
        try {
            return limit;
        } finally {
            lock.unlock();
        }
    }

    int busy() {
        lock.lock();
        try {
            return busy;
        } finally {
            lock.unlock();
        }
    }
}
