package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.core.persistence.AgentEntity;
import java.time.Instant;
import java.util.UUID;

/**
 * An agent as the layers above the services hold it: the row's properties, not the row.
 *
 * <p>In {@code access} rather than {@code agents} because this is what an agent key authenticates
 * to — {@code ApiKeyAuthService.agentFor} produces it for the principal — and because the claim in
 * {@code scanning} reads it, and {@code agents} sits above {@code scanning}. A service that writes
 * the agent's row reads the row itself, by {@link #id}.
 */
public record AgentView(
        UUID id,
        String name,
        String description,
        String kind,
        String labels,
        String credentialsMode,
        boolean enabled,
        Integer maxConcurrent,
        UUID apiKeyId,
        String hostname,
        String platform,
        String version,
        String scannerEngine,
        String capabilities,
        String contractVersion,
        String sealingPublicKey,
        String signingPublicKey,
        Instant lastSeenAt,
        Instant createdAt) {

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
