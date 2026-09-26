package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.core.persistence.ApiKeyEntity;
import java.time.Instant;
import java.util.UUID;

/**
 * An API key as the bearer filter holds it while it decides what the key stands for: the row's
 * properties, not the row — and not its hash, which nothing above the services has a use for.
 */
public record ApiKeyView(
        UUID id,
        String name,
        String prefix,
        Instant createdAt,
        Instant lastUsedAt,
        String scopes,
        String targetKind,
        Long targetId,
        Instant expiresAt,
        Long ownerUserId) {

    public static ApiKeyView of(ApiKeyEntity key) {
        return new ApiKeyView(
                key.getId(),
                key.getName(),
                key.getPrefix(),
                key.getCreatedAt(),
                key.getLastUsedAt(),
                key.getScopes(),
                key.getTargetKind(),
                key.getTargetId(),
                key.getExpiresAt(),
                key.getOwnerUserId());
    }
}
