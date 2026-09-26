package com.asmolabs.vectispire.core.agents.internal;

import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;

/**
 * The agent row as the principal and the claim hold it.
 *
 * <p>It was {@code AgentView.of}, beside the record in {@code access}, while the row was layered.
 * The row is {@code agents}' now, and {@code access} cannot name it (decision 0029): the record
 * stays where the principal needs it, the mapping moves to the module that owns what it maps.
 */
public final class AgentViews {

    private AgentViews() {}

    public static AgentView of(AgentEntity agent) {
        return new AgentView(
                agent.getId(),
                agent.getName(),
                agent.getDescription(),
                agent.getKind(),
                agent.getLabels(),
                agent.getCredentialsMode(),
                agent.getEnabled(),
                agent.getMaxConcurrent(),
                agent.getApiKeyId(),
                agent.getHostname(),
                agent.getPlatform(),
                agent.getVersion(),
                agent.getScannerEngine(),
                agent.getCapabilities(),
                agent.getContractVersion(),
                agent.getSealingPublicKey(),
                agent.getSigningPublicKey(),
                agent.getLastSeenAt(),
                agent.getCreatedAt());
    }
}
