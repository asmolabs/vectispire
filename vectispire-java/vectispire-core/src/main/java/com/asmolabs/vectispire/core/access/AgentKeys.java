package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeys;
import com.asmolabs.vectispire.common.domain.crypto.PasswordHasher;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyEntity;
import com.asmolabs.vectispire.core.access.persistence.ApiKeyRepository;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * The key a remote agent authenticates with, stored and removed for agent administration.
 *
 * <p><b>Here because the key table is this module's.</b> {@code agents} wrote {@code t_api_key}
 * through the repository while the code was packaged by layer, a dependency on access's storage
 * nothing showed. The agent row and its key still commit together: neither method opens a
 * transaction, so both join the one the caller holds — as the repository calls they replace did.
 */
@Service
public class AgentKeys {

    private final ApiKeyRepository keys;

    public AgentKeys(ApiKeyRepository keys) {
        this.keys = keys;
    }

    /**
     * Stores the hash of {@code issued} under {@code name} and answers the key's identifier, which
     * the insert generates — the agent row that points at it has to be saved after.
     */
    public UUID issue(String name, ApiKeys.IssuedKey issued, Instant at) {
        ApiKeyEntity key = new ApiKeyEntity();
        key.setName(name);
        key.setKeyHash(PasswordHasher.hash(issued.fullKey()));
        key.setPrefix(issued.prefix());
        // The only scope: an agent has no business reading the backlog or exporting anything.
        key.setScopes(ApiKeyScope.AGENT.wireName());
        key.setCreatedAt(at);
        return keys.save(key).getId();
    }

    /** Removes the key of a deleted agent: kept, it would be an open door to the protocol with no agent behind it. */
    public void revoke(UUID id) {
        keys.deleteById(id);
    }
}
