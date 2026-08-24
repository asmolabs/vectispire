package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.ApiKeyEntity;
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
public interface ApiKeysRepository extends JpaRepository<ApiKeyEntity, UUID> {

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
}
