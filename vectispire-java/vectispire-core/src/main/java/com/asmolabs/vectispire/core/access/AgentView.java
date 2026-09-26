package com.asmolabs.vectispire.core.access;

import java.time.Instant;
import java.util.UUID;

/**
 * An agent as the layers above the services hold it: the row's properties, not the row.
 *
 * <p>In {@code access} rather than {@code agents} because this is what an agent key authenticates
 * to — {@code ApiKeyAuthService.agentFor} produces it for the principal — and because the claim in
 * {@code scanning} reads it, and {@code agents} sits above {@code scanning}. The row itself is
 * {@code agents}' (decision 0029), which builds this record from it ({@code AgentViews}) and answers
 * {@link AgentDirectory}; a service that writes the agent's row reads the row itself, by {@link #id}.
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
        Long sealingKeyGeneration,
        String signingPublicKey,
        Instant lastSeenAt,
        Instant createdAt) {}
