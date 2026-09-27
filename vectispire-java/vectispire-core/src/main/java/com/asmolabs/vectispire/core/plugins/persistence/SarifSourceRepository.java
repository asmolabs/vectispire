package com.asmolabs.vectispire.core.plugins.persistence;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The declared internal SARIF sources. */
public interface SarifSourceRepository extends JpaRepository<SarifSourceEntity, Long> {

    List<SarifSourceEntity> findAllByOrderBySlugAsc();

    /** The source a key uploads for — the key names it, so there is at most one. */
    Optional<SarifSourceEntity> findByApiKeyId(UUID apiKeyId);

    boolean existsBySlug(String slug);

    boolean existsByApiKeyId(UUID apiKeyId);

    /**
     * The sources scoped to a project or a repository that is going away: a source with no scope
     * left would be a key that may deliver for nothing, and one day for whatever takes the id.
     */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from SarifSourceEntity s where s.projectId = :projectId")
    int deleteByProject(@Param("projectId") long projectId);

    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from SarifSourceEntity s where s.repositoryId = :repositoryId")
    int deleteByRepository(@Param("repositoryId") long repositoryId);
}
