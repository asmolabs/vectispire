package com.asmolabs.vectispire.core.access.persistence;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The API keys. */
public interface ApiKeyRepository extends JpaRepository<ApiKeyEntity, UUID> {

    /**
     * The candidates a presented key could be.
     *
     * <p>A list and not an optional: the prefix is nine random characters, so a collision is
     * unlikely and not impossible, and returning one row would make the second key with that
     * prefix silently unusable.
     */
    List<ApiKeyEntity> findByPrefix(String prefix);

    List<ApiKeyEntity> findAllByOrderByCreatedAtDesc();

    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ApiKeyEntity k set k.lastUsedAt = :at where k.id = :id")
    int markUsed(@Param("id") UUID id, @Param("at") Instant at);

    /**
     * The integration keys an account issued for itself, to be named one by one when a reset
     * revokes them — see {@code AccountAdminService#saveRevokingEverything}.
     */
    List<ApiKeyEntity> findByOwnerUserId(Long ownerUserId);

    /**
     * Revokes every integration key an account issued for itself — see
     * {@code AccountAdministrationService#update} for when.
     *
     * <p>An agent's key has no owner and is not touched: it belongs to the agent, and is revoked
     * with it.
     */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from ApiKeyEntity k where k.ownerUserId = :owner")
    int revokeOwnedBy(@Param("owner") long owner);

    /**
     * The integration keys restricted to one target, to be revoked with it — see
     * {@code TargetGrants#revokeAll}. An agent's key has no owner and is not among them.
     */
    @Query("select k from ApiKeyEntity k where k.targetKind = :kind and k.targetId = :targetId and k.ownerUserId is not null")
    List<ApiKeyEntity> findRestrictedTo(@Param("kind") String kind, @Param("targetId") long targetId);

    /** Revokes these keys: the row goes, as for a revocation by hand. Never asked with an empty list. */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from ApiKeyEntity k where k.id in :ids")
    int revokeByIds(@Param("ids") Collection<UUID> ids);
}
