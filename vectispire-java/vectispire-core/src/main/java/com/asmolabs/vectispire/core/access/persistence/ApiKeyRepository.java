package com.asmolabs.vectispire.core.access.persistence;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The API keys.
 *
 * <p>Named with the {@code Repository} suffix, alone among these, because {@code ApiKeys} is
 * already the domain's rule class and two types of the same simple name in one method do not
 * compile.
 */
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
     * Revokes the integration keys restricted to one target, with the target — see
     * {@code TargetGrants#revokeAll}.
     */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from ApiKeyEntity k where k.targetKind = :kind and k.targetId = :targetId and k.ownerUserId is not null")
    int revokeRestrictedTo(@Param("kind") String kind, @Param("targetId") long targetId);
}
