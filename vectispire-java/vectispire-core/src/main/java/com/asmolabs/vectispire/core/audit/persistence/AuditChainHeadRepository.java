package com.asmolabs.vectispire.core.audit.persistence;

import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** The lock every audit write takes before it reads the chain's head (V66). */
public interface AuditChainHeadRepository extends JpaRepository<AuditChainHeadEntity, Integer> {

    /**
     * {@code select … for update} on the one row, held until the entry's transaction ends: the next
     * writer, on this instance or another, waits here instead of reading the same head. Empty only if
     * V66's row was deleted by hand — which the caller refuses rather than writing unlocked.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select h from AuditChainHeadEntity h where h.id = :id")
    Optional<AuditChainHeadEntity> lock(@Param("id") int id);
}
