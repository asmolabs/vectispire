package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.LeaderLeaseEntity;
import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The leases that make a periodic job single-owner.
 *
 * <p>Every write is a conditional statement whose affected row count is the arbitration.
 * There is no {@code save} here on purpose: a merge would read, then write, and the winner
 * would be whoever wrote last rather than whoever met the condition.
 */
public interface LeaderLeases extends JpaRepository<LeaderLeaseEntity, String> {

    /** Renewal by the current holder. Conditioned on still being the holder. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update LeaderLeaseEntity l set l.expiresAt = :expiresAt, l.updatedAt = :at
             where l.name = :name and l.holder = :holder""")
    int renew(
            @Param("name") String name,
            @Param("holder") String holder,
            @Param("expiresAt") Instant expiresAt,
            @Param("at") Instant at);

    /**
     * Taking over an expired lease.
     *
     * <p>Conditioned on the holder <b>and</b> the expiry the caller just read: another
     * instance that took the lease in between changes both, this statement matches nothing,
     * and the caller loses rather than stealing a lease somebody legitimately holds.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update LeaderLeaseEntity l
               set l.holder = :holder, l.expiresAt = :expiresAt, l.acquiredAt = :at, l.updatedAt = :at
             where l.name = :name
               and (l.holder = :previousHolder or (:previousHolder is null and l.holder is null))
               and (l.expiresAt = :previousExpiry or (:previousExpiry is null and l.expiresAt is null))""")
    int takeOver(
            @Param("name") String name,
            @Param("holder") String holder,
            @Param("expiresAt") Instant expiresAt,
            @Param("at") Instant at,
            @Param("previousHolder") String previousHolder,
            @Param("previousExpiry") Instant previousExpiry);

    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update LeaderLeaseEntity l set l.holder = null, l.expiresAt = null, l.updatedAt = :at
             where l.name = :name and l.holder = :holder""")
    int release(@Param("name") String name, @Param("holder") String holder, @Param("at") Instant at);

    /**
     * First acquisition, as a bare insert.
     *
     * <p>Native, because JPQL has no insert and {@code save} would merge — turning "the
     * primary key arbitrates" into "the last writer wins".
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query(
            value = "insert into t_leader_lease (name, holder, acquired_at, expires_at, updated_at)"
                    + " values (:name, :holder, :acquiredAt, :expiresAt, :updatedAt)",
            nativeQuery = true)
    int insertNew(
            @Param("name") String name,
            @Param("holder") String holder,
            @Param("acquiredAt") Instant acquiredAt,
            @Param("expiresAt") Instant expiresAt,
            @Param("updatedAt") Instant updatedAt);
}
