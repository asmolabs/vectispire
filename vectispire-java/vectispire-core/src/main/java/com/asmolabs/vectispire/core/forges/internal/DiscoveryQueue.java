package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.DiscoveryReason;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryState;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

/**
 * The discoveries' queue: the claim, and the runs whose instance stopped answering (decision 0037 §3).
 *
 * <p><b>The scan queue's pattern</b>: the waiting runs read oldest first, each taken by a conditional update naming
 * the state it expects, so that of two control-plane instances racing on one run exactly one takes it; no row lock
 * is held, so no claim waits on another's.
 *
 * <p><b>A lease the run renews, and a restart that resumes.</b> A claim holds its run for {@link #LEASE}; the run
 * extends it before every request it sends, so only an instance that stopped — a restart, a crash — lets it lapse.
 * A lapsed run goes back to {@code pending} and is listed again from the first page by whichever instance takes it:
 * the snapshot is written by the forge's id, so a page read twice changes nothing. Three attempts, and a run still
 * lost is failed {@code executor_lost} — a discovery that brings its instance down every time is not handed to the
 * next one forever.
 */
@Component
public class DiscoveryQueue {

    /**
     * Longer than anything between two renewals: a request's twenty seconds, a rate-limit wait of up to a minute,
     * the back-offs — with room to spare.
     */
    static final Duration LEASE = Duration.ofMinutes(3);

    /** How many times a run is taken before a lost one is failed rather than resumed. */
    static final int MAX_ATTEMPTS = 3;

    /** How many waiting runs a claim reads before it gives up for this turn: a few lost races, no more. */
    static final int CANDIDATES = 8;

    private final ForgeDiscoveryRepository discoveries;
    private final Clock clock;

    public DiscoveryQueue(ForgeDiscoveryRepository discoveries, Clock clock) {
        this.discoveries = discoveries;
        this.clock = clock;
    }

    /** Takes the oldest waiting run for {@code owner}: its id, or empty when none was left to take. */
    public Optional<Long> claim(String owner) {
        Instant now = clock.instant();
        for (Long id : discoveries.waiting(DiscoveryState.PENDING.wireName(), PageRequest.of(0, CANDIDATES))) {
            if (discoveries.take(id, DiscoveryState.PENDING.wireName(), DiscoveryState.RUNNING.wireName(), owner, now,
                    now.plus(LEASE)) == 1) {
                return Optional.of(id);
            }
        }
        return Optional.empty();
    }

    /** Puts back every run whose lease lapsed, or fails it once its attempts are spent: how many were recovered. */
    public int recoverLapsed() {
        Instant now = clock.instant();
        int recovered = 0;
        for (Long id : discoveries.lapsed(DiscoveryState.RUNNING.wireName(), now)) {
            recovered += discoveries.requeueLapsed(id, DiscoveryState.RUNNING.wireName(),
                    DiscoveryState.PENDING.wireName(), now, MAX_ATTEMPTS);
            recovered += discoveries.failLapsed(id, DiscoveryState.RUNNING.wireName(), DiscoveryState.FAILED.wireName(),
                    DiscoveryReason.EXECUTOR_LOST.wireName(), "The instances that took this discovery stopped answering "
                            + MAX_ATTEMPTS + " times before it ended. What it listed is kept; request it again.",
                    now, MAX_ATTEMPTS);
        }
        return recovered;
    }
}
