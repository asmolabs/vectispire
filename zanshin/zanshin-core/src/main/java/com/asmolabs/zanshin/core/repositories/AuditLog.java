package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.AuditLogEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLog extends JpaRepository<AuditLogEntity, UUID> {
    /**
     * The whole log in chain order.
     *
     * <p>Ordered by instant then id, which is the order the integrity chain was written in
     * and the only one verification can follow. Two entries written in the same millisecond
     * by two instances are a legitimate fork, and the id breaks the tie deterministically.
     */
    List<AuditLogEntity> findAllByOrderByTimestampAscIdAsc();

    /**
     * The entry the next one chains onto.
     *
     * <p>Same ordering as the verification, reversed. Reading "the latest" by timestamp
     * alone would pick either of two entries written in the same millisecond, and the chain
     * would then be built onto one and verified against the other.
     */
    Optional<AuditLogEntity> findTopByOrderByTimestampDescIdDesc();

    /** The newest entries, for the screen. */
    @Query("select a from AuditLogEntity a order by a.timestamp desc, a.id desc")
    List<AuditLogEntity> findRecent(Limit limit);

    /**
     * Rewrites one entry's hashes. Used by the rebuild, and by nothing else.
     *
     * <p>A targeted update rather than a save: loading the entity would let a dirty check
     * rewrite columns the rebuild has no business touching, on a table whose whole purpose
     * is that its rows do not change.
     */
    @Modifying(clearAutomatically = true)
    @Query("update AuditLogEntity a set a.previousHash = :previousHash, a.entryHash = :entryHash where a.id = :id")
    int updateHashes(
            @Param("id") UUID id,
            @Param("previousHash") String previousHash,
            @Param("entryHash") String entryHash);
}
