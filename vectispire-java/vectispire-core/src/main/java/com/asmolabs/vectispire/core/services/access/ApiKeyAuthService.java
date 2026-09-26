package com.asmolabs.vectispire.core.services.access;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeys;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.persistence.UserEntity;
import com.asmolabs.vectispire.core.repositories.Agents;
import com.asmolabs.vectispire.core.repositories.ApiKeysRepository;
import com.asmolabs.vectispire.core.repositories.Users;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Authentication by API key.
 *
 * <p><b>The prefix is what makes this practical.</b> Without it, checking a key would cost one
 * password verification per existing key on every request — a denial of service offered to
 * whoever presents anything at all. The twelve-character prefix, stored in the clear because it
 * is not a secret, narrows the candidates to one or two.
 *
 * <p><b>An expired key is refused but its row is kept.</b> The audit trail needs to know it
 * existed, and an operator who sees "expired" understands more than one who sees nothing.
 */
@Service
public class ApiKeyAuthService {

    private final ApiKeysRepository keys;
    private final Agents agents;
    private final Clock clock;
    private final Users users;

    public ApiKeyAuthService(ApiKeysRepository keys, Agents agents, Clock clock, Users users) {
        this.keys = keys;
        this.agents = agents;
        this.clock = clock;
        this.users = users;
    }

    /**
     * What an integration key stands for (decision 0024).
     *
     * @param owner the active account it acts for — its role applies, and its visibility
     * @param restriction the key's own narrowing, intersected with the account's by every route
     */
    public record Integration(
            UserEntity owner, UUID keyId, String keyName, Set<ApiKeyScope> scopes, Visibility restriction) {}

    /**
     * The account and narrowing an integration key carries, or empty when it carries none.
     *
     * <p>Empty for an agent's key (those are resolved to their agent), for a key issued before keys
     * had an owner, and for a key whose account is gone or deactivated: a key must not outlive the
     * account whose authority it borrows.
     */
    @Transactional(readOnly = true)
    public Optional<Integration> integrationFor(ApiKeyEntity key) {
        if (hasScope(key, ApiKeyScope.AGENT) || key.getOwnerUserId() == null) {
            return Optional.empty();
        }
        Set<ApiKeyScope> scopes = EnumSet.noneOf(ApiKeyScope.class);
        for (ApiKeyScope scope : ApiKeyScope.values()) {
            if (scope != ApiKeyScope.AGENT && hasScope(key, scope)) {
                scopes.add(scope);
            }
        }
        return users.findById(key.getOwnerUserId())
                .filter(UserEntity::getIsActive)
                .map(owner -> new Integration(owner, key.getId(), key.getName(), Set.copyOf(scopes), restrictionOf(key)));
    }

    /** Everything when unrestricted; otherwise the one target the key was issued for. */
    private static Visibility restrictionOf(ApiKeyEntity key) {
        if (key.getTargetKind() == null || key.getTargetId() == null) {
            return Visibility.everything();
        }
        return switch (key.getTargetKind()) {
            case "repository" -> Visibility.only(List.of(new ScanTarget.Repository(key.getTargetId())));
            case "container" -> Visibility.only(List.of(new ScanTarget.Container(key.getTargetId())));
            // A kind nobody wrote is a key nobody understands: it sees nothing, never everything.
            default -> Visibility.only(List.of());
        };
    }

    /**
     * The key when it is usable, empty otherwise.
     *
     * <p>It never says <em>why</em>: telling "unknown" from "expired" tells whoever is probing
     * which half of a guess was right.
     */
    @Transactional
    public Optional<ApiKeyEntity> resolve(String presented) {
        String trimmed = presented == null ? "" : presented.trim();
        if (trimmed.length() <= ApiKeys.PREFIX_LENGTH) {
            return Optional.empty();
        }

        Instant asOf = clock.instant();
        for (ApiKeyEntity candidate : keys.findByPrefix(trimmed.substring(0, ApiKeys.PREFIX_LENGTH))) {
            if (!PasswordHasher.verify(trimmed, candidate.getKeyHash())) {
                continue;
            }
            if (candidate.getExpiresAt() != null && !candidate.getExpiresAt().isAfter(asOf)) {
                return Optional.empty();
            }

            // `lastUsedAt` is set without waiting: it is the only trace that lets an operator
            // spot a key issued for a use that never happened.
            keys.markUsed(candidate.getId(), asOf);
            return Optional.of(candidate);
        }
        return Optional.empty();
    }

    /** Does this key carry that scope? */
    public boolean hasScope(ApiKeyEntity key, ApiKeyScope scope) {
        String scopes = key.getScopes() == null ? "" : key.getScopes();
        return Arrays.stream(scopes.split(",")).map(String::trim).anyMatch(scope.wireName()::equals);
    }

    /** The agent this key belongs to, if there is one. */
    @Transactional(readOnly = true)
    public Optional<AgentEntity> agentFor(ApiKeyEntity key) {
        return agents.findByApiKeyId(key.getId());
    }
}
