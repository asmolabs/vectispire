package com.asmolabs.vectispire.core.services.scanning;

import java.time.Instant;
import java.util.UUID;

/**
 * The claimant's own row, written first so that two claims by one agent commit one after the other.
 *
 * <p>See {@link ScanQueue#claimWithin} for why the count and the take must sit behind a lock, and
 * why the lock is a write. <b>A port, because the row is {@code agents}'</b>: the queue used to
 * update {@code t_agent} through the agent repository, which kept the row layered — {@code agents}
 * claims through the queue, so the queue cannot use {@code agents}. Declared here and implemented by
 * the module that owns the row (decision 0029), it is the same update in the same transaction.
 */
public interface AgentClaimLock {

    /**
     * Takes the lock inside the caller's transaction.
     *
     * @return false when the agent no longer exists — nothing to claim for
     */
    boolean lockForClaim(UUID agentId, Instant at);
}
