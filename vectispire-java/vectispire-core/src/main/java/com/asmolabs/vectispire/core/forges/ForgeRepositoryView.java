package com.asmolabs.vectispire.core.forges;

import java.time.Instant;
import java.util.UUID;

/**
 * One repository of a connection's snapshot (decision 0037 §3). Every metadata component is null when the forge
 * did not give it — unknown is not zero: a {@code null} size is not a small repository, a {@code null} fork not an
 * original, a {@code null} language not a repository without one.
 *
 * @param forgeId the forge's own id, stable across renames and moves
 * @param personal held in a user's own namespace: offered unticked by the selection
 * @param firstSeenBy the discovery that listed it first
 * @param lastSeenBy the last discovery that listed it
 * @param changedBy the last discovery that found it renamed or moved, re-branched, archived or back; {@code
 *     changeSummary} says what
 * @param goneBy the completed discovery that no longer listed it; null while it is listed
 */
public record ForgeRepositoryView(
        long id,
        UUID connectionId,
        String forgeId,
        String fullPath,
        String namespacePath,
        boolean personal,
        String name,
        String defaultBranch,
        Boolean archived,
        Boolean fork,
        String visibility,
        Instant lastActivityAt,
        String language,
        Long sizeBytes,
        String httpUrl,
        String sshUrl,
        String webUrl,
        long firstSeenBy,
        Instant firstSeenAt,
        long lastSeenBy,
        Instant lastSeenAt,
        Long changedBy,
        String changeSummary,
        Long goneBy,
        Instant goneAt) {}
