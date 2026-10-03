package com.asmolabs.vectispire.core.forges.persistence;

import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The provenance of imported targets (decision 0037 §5), keyed by connection and forge id. */
public interface ForgeImportLinkRepository extends JpaRepository<ForgeImportLinkEntity, Long> {

    /** The links of these repositories of the connection; called with at most one import's thousand ids. */
    List<ForgeImportLinkEntity> findByConnectionIdAndForgeIdIn(UUID connectionId, Collection<String> forgeIds);

    /** Every link of the connection: the selection table flags what it imported, its snapshot being bounded too. */
    List<ForgeImportLinkEntity> findByConnectionId(UUID connectionId);

    /** How many targets the connection imported, as its listing shows it. */
    long countByConnectionId(UUID connectionId);

    /** A deleted target's link, in the deleting transaction ({@code TargetDeleted}). */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ForgeImportLinkEntity l where l.repositoryId = :repositoryId")
    int deleteByRepository(@Param("repositoryId") long repositoryId);

    /** A deleted connection's links; its targets stay. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ForgeImportLinkEntity l where l.connectionId = :connectionId")
    int deleteByConnection(@Param("connectionId") UUID connectionId);
}
