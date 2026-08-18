package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.ScanEntity;
import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
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
public interface Scans extends JpaRepository<ScanEntity, Long> {

    long countByStatus(String status);

    /**
     * How many scans of this target are already waiting.
     *
     * <p>Asked before queueing another: a target whose previous scan has not started yet does
     * not need a second, and stacking them grows the queue without learning anything.
     */
    long countByStatusAndRepoId(String status, Long repoId);

    long countByStatusAndContainerId(String status, Long containerId);

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
    @Transactional
    @Modifying(clearAutomatically = true)
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

    /**
     * Extends the lease of a scan that is still progressing.
     *
     * <p>The owner is in the {@code where}, not checked beforehand: a worker whose lease already
     * lapsed and whose scan was taken over must renew nothing, and reading then writing would
     * leave exactly the window in which it could.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s set s.leaseExpiresAt = :leaseExpiresAt
             where s.id = :id and s.status = :status and s.claimedBy = :worker""")
    int renewLease(
            @Param("id") Long id,
            @Param("status") String status,
            @Param("worker") String worker,
            @Param("leaseExpiresAt") Instant leaseExpiresAt);

    /**
     * Hands a scan back to the queue, or fails it, and <b>drops its lease</b> either way.
     *
     * <p>A failed scan that kept its lease would be picked up by the next reclaim, fail again,
     * and go round until its attempts ran out.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s
               set s.status = :to, s.error = :error, s.claimedBy = null,
                   s.claimedAt = null, s.leaseExpiresAt = null
             where s.id = :id""")
    int release(@Param("id") Long id, @Param("to") String to, @Param("error") String error);

    /** Scans whose lease has lapsed: their worker stopped renewing, or stopped existing. */
    @Query("""
            select s from ScanEntity s
             where s.status = :status
               and (s.leaseExpiresAt is null or s.leaseExpiresAt < :asOf)""")
    List<ScanEntity> findLapsed(@Param("status") String status, @Param("asOf") Instant asOf);

    /**
     * The scans that still carry a raw payload, newest first, with only the deciding columns.
     *
     * <p><b>Newest first is not cosmetic</b>: the retention rule ranks a target's scans in that
     * order to decide which fall outside the keep window. Any other sort would purge the most
     * recent scans — precisely the ones the payloads exist for — and nothing would say so.
     *
     * <p>Columns rather than entities, because loading the entities would read back the
     * megabytes this purge exists to stop carrying.
     */
    @Query("""
            select s.id, s.repoId, s.containerId, s.createdAt from ScanEntity s
             where s.sbom is not null or s.cves is not null
             order by s.createdAt desc, s.id desc""")
    List<Object[]> findPayloadBearing();

    @Query("select count(s.id) from ScanEntity s where s.sbom is not null or s.cves is not null")
    long countPayloadBearing();

    /**
     * Erases the raw payloads of a batch of scans.
     *
     * <p>A bulk update, and the columns are set to a real SQL {@code null}. Going through an
     * entity risks writing a JSON {@code null} literal into a JSON column, which satisfies
     * {@code is not null}: the purge would then re-select the same rows on every pass, free
     * nothing, and report a perfectly credible count.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ScanEntity s set s.sbom = null, s.cves = null where s.id in :ids")
    int dropPayloads(@Param("ids") Collection<Long> ids);

    /**
     * Each repository's most recent scan, as the target list shows it.
     *
     * <p>A correlated subquery rather than a join on a computed maximum: the latter returns two
     * rows when two scans of one target share a creation instant, and the list would then show
     * a target twice with no explanation.
     */
    @Query("""
            select s.repoId, s.id, s.status, s.createdAt, s.error from ScanEntity s
             where s.repoId is not null
               and s.id = (select max(l.id) from ScanEntity l where l.repoId = s.repoId)""")
    List<Object[]> findLatestPerRepository();

    @Query("""
            select s.containerId, s.id, s.status, s.createdAt, s.error from ScanEntity s
             where s.containerId is not null
               and s.id = (select max(l.id) from ScanEntity l where l.containerId = s.containerId)""")
    List<Object[]> findLatestPerContainer();

    /**
     * The history, newest first, optionally narrowed to one target.
     *
     * <p>Both filters are optional and expressed with a null check rather than as three query
     * methods: three methods is three orderings to keep in step, and the day one of them drifts
     * the screen shows a different history depending on which filter is set.
     */
    @Query("""
            select s from ScanEntity s
             where (:repoId is null or s.repoId = :repoId)
               and (:containerId is null or s.containerId = :containerId)
             order by s.createdAt desc, s.id desc""")
    List<ScanEntity> findHistory(
            @Param("repoId") Long repoId, @Param("containerId") Long containerId, Limit limit);
}
