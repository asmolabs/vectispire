package com.asmolabs.vectispire.core.forges.persistence;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The snapshot of a connection's repositories, keyed by the forge's own id (decision 0037 §3). */
public interface ForgeRepositoryRepository extends JpaRepository<ForgeRepositoryEntity, Long> {

    /** One page's repositories as the snapshot knows them; a page is a hundred, far under any bind limit. */
    List<ForgeRepositoryEntity> findByConnectionIdAndForgeIdIn(UUID connectionId, Collection<String> forgeIds);

    long countByConnectionIdAndFirstSeenBy(UUID connectionId, long discoveryId);

    long countByConnectionIdAndChangedBy(UUID connectionId, long discoveryId);

    /**
     * Marks gone every repository of the connection the completed run {@code discoveryId} did not list, and that
     * no run had marked gone already: how many. Only a completed run calls this — a partial listing proves
     * nothing about what it did not reach.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ForgeRepositoryEntity r set r.goneBy = :discoveryId, r.goneAt = :at
             where r.connectionId = :connectionId and r.lastSeenBy <> :discoveryId and r.goneBy is null""")
    int markGone(@Param("connectionId") UUID connectionId, @Param("discoveryId") long discoveryId, @Param("at") Instant at);

    /** The language a run asked for after listing, or unknown. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ForgeRepositoryEntity r set r.language = :language where r.connectionId = :connectionId and r.forgeId = :forgeId")
    int setLanguage(@Param("connectionId") UUID connectionId, @Param("forgeId") String forgeId,
            @Param("language") String language);

    Page<ForgeRepositoryEntity> findByConnectionIdAndLastSeenBy(UUID connectionId, long discoveryId, Pageable page);

    Page<ForgeRepositoryEntity> findByConnectionIdAndFirstSeenBy(UUID connectionId, long discoveryId, Pageable page);

    Page<ForgeRepositoryEntity> findByConnectionIdAndChangedBy(UUID connectionId, long discoveryId, Pageable page);

    Page<ForgeRepositoryEntity> findByConnectionIdAndGoneBy(UUID connectionId, long discoveryId, Pageable page);

    /** The snapshot of a connection that is going away; after its runs (see {@code ForgeDiscoveryRepository}). */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ForgeRepositoryEntity r where r.connectionId = :connectionId")
    int deleteByConnection(@Param("connectionId") UUID connectionId);
}
