package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.forges.DiscoveryReason;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryState;
import com.asmolabs.vectispire.common.domain.forges.UnreadableNamespace;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * One discovery as a route shows it (decision 0037 §3): where it stands, what it has read so far, and once it ended
 * how the snapshot moved. Polled by the screen while it runs.
 *
 * @param reason the closed word of a partial or failed run; null otherwise
 * @param attempts how many times an instance took it — more than one when a restart resumed it
 * @param repositoriesSkipped listed and not kept: an id, a path or a name longer than its column
 * @param rateLimitWaitSeconds the time spent waiting on rate limits inside the run
 * @param rateLimitResetAt when a rate limit that ended the run partial lifts
 * @param newCount repositories this run listed for the first time; null until it ends
 * @param changedCount repositories it found renamed or moved, with a new default branch, archived or back; null
 *     until it ends
 * @param goneCount repositories no longer listed — written by a completed run only, null for any other: a partial
 *     listing proves nothing about what it did not reach
 * @param unreadableNamespaces the namespaces the token could not read — an organisation behind single sign-on, an
 *     IP allow list, a policy refusing the token — each with its reason; a path of {@code null} for namespaces the
 *     forge withheld without naming them. None of their repositories is marked gone by this run. Empty when the
 *     run read everything it was shown
 */
public record ForgeDiscoveryView(
        long id,
        UUID connectionId,
        DiscoveryState state,
        DiscoveryReason reason,
        String detail,
        Instant requestedAt,
        String requestedBy,
        int attempts,
        Instant startedAt,
        Instant finishedAt,
        int namespacesSeen,
        int repositoriesSeen,
        int repositoriesSkipped,
        int requestsMade,
        long rateLimitWaitSeconds,
        Instant rateLimitResetAt,
        Integer newCount,
        Integer changedCount,
        Integer goneCount,
        List<UnreadableNamespace> unreadableNamespaces) {}
