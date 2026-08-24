package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.GatePolicyEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The gate policies: one global, plus one per target that overrides it.
 *
 * <p>{@code isActive} is {@code Boolean} and {@code null} means "superseded", for the reason
 * given in {@code RuleSets}: the unique index that enforces "at most one active per scope" only
 * counts NULLs as distinct. Old versions are kept rather than deleted — a build that failed
 * last month failed under rules somebody must still be able to read.
 */
public interface GatePolicies extends JpaRepository<GatePolicyEntity, Long> {

    List<GatePolicyEntity> findByIsActiveTrue();

    Optional<GatePolicyEntity> findByTargetKindAndTargetIdAndIsActiveTrue(String targetKind, Long targetId);

    @Query("select coalesce(max(p.version), 0) from GatePolicyEntity p where p.targetKind = :kind and p.targetId = :id")
    int highestVersion(@Param("kind") String targetKind, @Param("id") Long targetId);

    /** Supersedes the current policy of one scope, so a new version can take its place. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update GatePolicyEntity p set p.isActive = null
             where p.targetKind = :kind and p.targetId = :id and p.isActive = true""")
    int supersede(@Param("kind") String targetKind, @Param("id") Long targetId);

    @Transactional
    @Modifying
    @Query("delete from GatePolicyEntity p where p.targetKind = :kind and p.targetId = :id")
    int deleteByTarget(@Param("kind") String targetKind, @Param("id") Long targetId);
}
