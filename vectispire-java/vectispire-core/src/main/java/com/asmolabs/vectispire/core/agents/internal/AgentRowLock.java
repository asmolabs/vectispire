package com.asmolabs.vectispire.core.agents.internal;

import com.asmolabs.vectispire.core.agents.persistence.Agents;
import com.asmolabs.vectispire.core.scanning.AgentClaimLock;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The queue's {@link AgentClaimLock}: the update on the agent's row that {@code Agents.lockForClaim}
 * documents.
 *
 * <p>{@code MANDATORY}, because a lock taken in a transaction of its own is released at once and
 * serializes nothing — the two polls it exists for would both count below the limit and both take.
 */
@Component
public class AgentRowLock implements AgentClaimLock {

    private final Agents agents;

    public AgentRowLock(Agents agents) {
        this.agents = agents;
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public boolean lockForClaim(UUID agentId, Instant at) {
        return agents.lockForClaim(agentId, at) > 0;
    }
}
