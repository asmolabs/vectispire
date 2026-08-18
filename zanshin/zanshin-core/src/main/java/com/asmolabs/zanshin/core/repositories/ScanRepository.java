package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.ScanEntity;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.QueryHint;

/**
 * The scan queue, whose claim is the whole point.
 *
 * <p><b>The claim is transactional.</b> {@code SELECT … FOR UPDATE SKIP LOCKED} gives the
 * calling transaction exclusive ownership of the selected rows and lets a concurrent claimant
 * <em>step over</em> them instead of blocking — which is what lets several instances share one
 * queue without serializing on the oldest row. The status change and the lock release happen in
 * the same commit, so there is no window in which a row is claimed without saying so.
 *
 * <p><b>The routing filter lives inside the locking query, never after it.</b> Taking rows and
 * handing back the ones that do not fit would lock work destined for other agents and starve
 * them for the length of the transaction.
 *
 * <p><b>Ask for exactly what is needed, and retry.</b> The obvious idea — lock a wider window
 * then trim it — was tried and made PostgreSQL fail the very tests MySQL was failing: a
 * claimant holding rows it will not take starves the others for as long as it holds them.
 */
public interface ScanRepository extends JpaRepository<ScanEntity, Long> {

    long countByStatus(String status);

    /**
     * The rows this claimant is allowed to take, locked.
     *
     * <p>{@code jakarta.persistence.lock.timeout = -2} is Hibernate's {@code SKIP_LOCKED}. Left
     * out, the query <em>waits</em> for whoever holds the row instead of stepping over it, and
     * several instances sharing a queue serialize on its oldest entry — the slow failure that
     * looks like a busy database rather than like a missing hint.
     *
     * @param labels the agent's capabilities; a scan requiring none goes to anyone
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(@QueryHint(name = "jakarta.persistence.lock.timeout", value = "-2"))
    @Query("""
            select s from ScanEntity s
             where s.status = :status
               and (s.requiredAgentLabel is null or s.requiredAgentLabel in :labels)
             order by s.createdAt asc, s.id asc""")
    List<ScanEntity> lockClaimable(
            @Param("status") String status, @Param("labels") Collection<String> labels, Limit limit);

    /**
     * The same selection without a lock, for an engine that has none.
     *
     * <p>Paired with {@link #take}: the candidates are read, then each is taken by a
     * conditional update whose {@code where} still says {@code pending}. A row somebody else
     * took in between updates zero rows and drops out of the batch.
     */
    @Query("""
            select s from ScanEntity s
             where s.status = :status
               and (s.requiredAgentLabel is null or s.requiredAgentLabel in :labels)
             order by s.createdAt asc, s.id asc""")
    List<ScanEntity> findClaimable(
            @Param("status") String status, @Param("labels") Collection<String> labels, Limit limit);

    /**
     * The same two queries for an agent that carries no label at all.
     *
     * <p>Written out rather than passing an empty collection: {@code in ()} is a syntax error on
     * several engines, and the usual workaround — a sentinel value nothing equals — is a magic
     * string that has to stay impossible forever. It also stopped being impossible the moment it
     * contained a NUL byte, which PostgreSQL refuses outright.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @QueryHints(@QueryHint(name = "jakarta.persistence.lock.timeout", value = "-2"))
    @Query("""
            select s from ScanEntity s
             where s.status = :status and s.requiredAgentLabel is null
             order by s.createdAt asc, s.id asc""")
    List<ScanEntity> lockClaimableUnlabelled(@Param("status") String status, Limit limit);

    @Query("""
            select s from ScanEntity s
             where s.status = :status and s.requiredAgentLabel is null
             order by s.createdAt asc, s.id asc""")
    List<ScanEntity> findClaimableUnlabelled(@Param("status") String status, Limit limit);

    /**
     * Takes one row, and says whether it was still there to take.
     *
     * <p>{@code status = :from} in the {@code where} is what makes this safe without a lock:
     * two claimants racing on the same row both issue the update, and exactly one of them
     * changes a row.
     */
    @org.springframework.transaction.annotation.Transactional
    @org.springframework.data.jpa.repository.Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s
               set s.status = :to, s.claimedBy = :worker, s.claimedAt = :claimedAt,
                   s.leaseExpiresAt = :leaseExpiresAt, s.attempts = s.attempts + 1
             where s.id = :id and s.status = :from""")
    int take(
            @Param("id") Long id,
            @Param("from") String from,
            @Param("to") String to,
            @Param("worker") String worker,
            @Param("claimedAt") Instant claimedAt,
            @Param("leaseExpiresAt") Instant leaseExpiresAt);

    /** Scans whose lease has lapsed: their worker stopped renewing, or stopped existing. */
    @Query("""
            select s from ScanEntity s
             where s.status = :status
               and (s.leaseExpiresAt is null or s.leaseExpiresAt < :asOf)""")
    List<ScanEntity> findLapsed(@Param("status") String status, @Param("asOf") Instant asOf);
}
