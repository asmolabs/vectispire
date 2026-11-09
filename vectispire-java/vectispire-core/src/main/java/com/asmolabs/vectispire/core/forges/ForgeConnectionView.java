package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.forges.ForgeConnectionState;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * A forge connection as a route shows it — <b>never its token</b> (decision 0037 §2).
 *
 * @param kind {@code github} or {@code gitlab}
 * @param edition which deployment, derived from the address: {@code github_com}, {@code
 *     github_data_residency}, {@code github_enterprise_server}, {@code gitlab_com}, {@code gitlab_self_managed}
 * @param baseUrl the web address, from which the API's is derived
 * @param owner GitHub's organisation or user; null for GitLab
 * @param internalNetwork whether the administrator stated the server is internal ({@code INTERNAL_ALLOWED});
 *     always false for a cloud edition
 * @param caSubject the pinned CA's subject; null when the runtime's trust store is used
 * @param caNotAfter the pinned CA bundle's earliest expiry — past it the server is no longer reachable
 * @param credentialKind what the forge identified: {@code github_fine_grained}, {@code github_classic},
 *     {@code gitlab_bot} (a group or project access token), {@code gitlab_personal}
 * @param scopes as the forge reported them; null when it reports none — a GitHub fine-grained token, whose
 *     permissions are not readable
 * @param canWrite whether the token can write to a repository — true for a classic GitHub token holding
 *     {@code repo} or {@code public_repo}, accepted on Enterprise Server only and flagged; null when the forge
 *     does not say
 * @param tokenExpiresAt the expiry the forge reported; null when none was
 * @param forgeVersion the server's version at the last probe; null for the clouds
 * @param probedAt when the token was last presented and accepted
 * @param encryptionState {@code current}, {@code previous_key} (rotate: save the connection or replace its
 *     token) or {@code unreadable} (replace the token)
 * @param state {@code active}, or {@code suspended} when the integration of its forge is disabled (decision 0040
 *     §2): kept with its token, used for nothing until a platform governor enables the forge again
 * @param integration the registry's key of its forge, {@code forge.gitlab} or {@code forge.github}: what a
 *     governor switches to resume a suspended connection
 * @param lastDiscovery the connection's latest discovery, whatever its state; null before the first
 * @param importedTargets how many targets were imported through it and still exist — a deleted target's link goes
 *     with it
 */
public record ForgeConnectionView(
        UUID id,
        String name,
        String kind,
        String edition,
        String baseUrl,
        String owner,
        boolean internalNetwork,
        String caSubject,
        Instant caNotAfter,
        String credentialKind,
        List<String> scopes,
        Boolean canWrite,
        Instant tokenExpiresAt,
        String forgeVersion,
        Instant probedAt,
        String encryptionState,
        ForgeConnectionState state,
        String integration,
        Instant createdAt,
        String createdBy,
        Instant updatedAt,
        String updatedBy,
        ForgeDiscoveryView lastDiscovery,
        long importedTargets) {}
