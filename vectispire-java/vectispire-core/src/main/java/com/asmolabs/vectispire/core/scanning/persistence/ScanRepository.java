package com.asmolabs.vectispire.core.scanning.persistence;

import com.asmolabs.vectispire.core.scanning.persistence.queries.LatestScanRow;
import jakarta.persistence.LockModeType;
import jakarta.persistence.QueryHint;
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
     * The claimable selection in claim order, a page at a time, for an agent that cannot be handed a
     * delegated credential (decision 0031) — see {@code ScanQueue.claimWithin}.
     *
     * <p><b>A page of columns, not a list of exclusions.</b> This used to be the same selection with
     * {@code and s.repoId not in :excluded}, the list being every waiting repository that carries a
     * credential: bounded by nothing but the queue, and one bind parameter per repository. Past the
     * engines' limits — 65,535 for the PostgreSQL driver and a MySQL server-side statement, 32,766 in
     * SQLite's default build — the claim itself failed, at every poll of every such agent. The caller
     * now reads a page, asks which of <em>its</em> repositories carry a credential, and goes on past
     * the page's last row; no statement carries more than a page.
     *
     * <p>The position is the order's own key, {@code (createdAt, id)}, so the next page starts
     * exactly after the last row read whatever was taken or queued in between. Two statements rather
     * than a null position, which PostgreSQL cannot type when it is bound as null.
     */
    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.ClaimCandidate(s.id, s.repoId, s.createdAt)
              from ScanEntity s
             where s.status = :status
               and (s.requiredAgentLabel is null or s.requiredAgentLabel in :labels)
             order by s.createdAt asc, s.id asc""")
    List<ClaimCandidate> findClaimablePage(
            @Param("status") String status, @Param("labels") Collection<String> labels, Limit limit);

    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.ClaimCandidate(s.id, s.repoId, s.createdAt)
              from ScanEntity s
             where s.status = :status
               and (s.requiredAgentLabel is null or s.requiredAgentLabel in :labels)
               and (s.createdAt > :afterAt or (s.createdAt = :afterAt and s.id > :afterId))
             order by s.createdAt asc, s.id asc""")
    List<ClaimCandidate> findClaimablePageAfter(
            @Param("status") String status,
            @Param("labels") Collection<String> labels,
            @Param("afterAt") Instant afterAt,
            @Param("afterId") Long afterId,
            Limit limit);

    /** The two pages for an agent that carries no label — {@code in ()} is not valid everywhere. */
    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.ClaimCandidate(s.id, s.repoId, s.createdAt)
              from ScanEntity s
             where s.status = :status and s.requiredAgentLabel is null
             order by s.createdAt asc, s.id asc""")
    List<ClaimCandidate> findClaimableUnlabelledPage(@Param("status") String status, Limit limit);

    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.ClaimCandidate(s.id, s.repoId, s.createdAt)
              from ScanEntity s
             where s.status = :status and s.requiredAgentLabel is null
               and (s.createdAt > :afterAt or (s.createdAt = :afterAt and s.id > :afterId))
             order by s.createdAt asc, s.id asc""")
    List<ClaimCandidate> findClaimableUnlabelledPageAfter(
            @Param("status") String status,
            @Param("afterAt") Instant afterAt,
            @Param("afterId") Long afterId,
            Limit limit);

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
     * Hands a scan back to the queue, or fails it, and <b>drops its lease</b> either way — if the
     * caller still holds it.
     *
     * <p>A failed scan that kept its lease would be picked up by the next reclaim, fail again,
     * and go round until its attempts ran out.
     *
     * <p><b>The owner is in the {@code where}</b>, as in {@link #renewLease}. This update used to
     * name the row by id alone: a worker whose lease had lapsed and whose scan had been taken over
     * could still fail it, marking its successor's work FAILED and dropping the successor's lease.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s
               set s.status = :to, s.error = :error, s.claimedBy = null,
                   s.claimedAt = null, s.leaseExpiresAt = null
             where s.id = :id and s.status = :running and s.claimedBy = :owner""")
    int releaseOwned(
            @Param("id") Long id,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("to") String to,
            @Param("error") String error);

    /**
     * {@link #releaseOwned}, for one attempt of the scan only: what an agent's failure report applies.
     *
     * <p><b>The attempt is in the {@code where}</b>, beside the owner. A report names the attempt it
     * is about; without it, a report delayed or sent twice would reach the next attempt when the same
     * agent had taken the scan again — requeued by the first report, claimed by the next poll — and
     * spend an attempt that had not failed.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s
               set s.status = :to, s.error = :error, s.claimedBy = null,
                   s.claimedAt = null, s.leaseExpiresAt = null
             where s.id = :id and s.status = :running and s.claimedBy = :owner and s.attempts = :attempt""")
    int releaseOwnedAttempt(
            @Param("id") Long id,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("attempt") int attempt,
            @Param("to") String to,
            @Param("error") String error);

    /**
     * Hands a scan back to the queue as {@link #releaseOwned} does, and gives back the attempt its
     * claim counted.
     *
     * <p>For a claim that turned out to be one nobody could have honoured — a delegated credential
     * withheld from an agent whose selection did not know the repository needed one. Its own
     * statement rather than a flag on {@code releaseOwned}, so that no failure path can refund by a
     * wrong argument: a refund on a path that can repeat is a scan that circulates for ever. Never
     * below zero, although the claim being refunded counted one: the release must not depend on it.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s
               set s.status = :to, s.error = null, s.claimedBy = null,
                   s.claimedAt = null, s.leaseExpiresAt = null,
                   s.attempts = case when s.attempts > 0 then s.attempts - 1 else 0 end
             where s.id = :id and s.status = :running and s.claimedBy = :owner""")
    int releaseOwnedRefunded(
            @Param("id") Long id,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("to") String to);

    /**
     * The same, for the reclaim: releases a scan only while its lease is still lapsed.
     *
     * <p>The reclaim reads the lapsed scans and then releases them; in between, the owner may
     * renew or finish. Conditioning on the lease is enough — no successor can have taken a scan
     * that is still {@code scanning}, so only the owner can have changed the row, and either of its
     * moves makes this match nothing.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s
               set s.status = :to, s.error = :error, s.claimedBy = null,
                   s.claimedAt = null, s.leaseExpiresAt = null
             where s.id = :id and s.status = :running
               and (s.leaseExpiresAt is null or s.leaseExpiresAt < :asOf)""")
    int releaseLapsed(
            @Param("id") Long id,
            @Param("running") String running,
            @Param("asOf") Instant asOf,
            @Param("to") String to,
            @Param("error") String error);

    /**
     * The targets that have at least one scan in this status, as {@code [repoId, containerId]}.
     *
     * <p><b>Columns, not entities.</b> Asked by routes that need only "has a target the caller may
     * see completed a scan" — and answered by loading every scan in the deployment, SBOM and CVE
     * payloads included, to read one boolean off them. The allowance is a set of targets, so it is
     * still applied in memory; what no longer travels is the payload.
     */
    @Query("select distinct s.repoId, s.containerId from ScanEntity s where s.status = :status")
    List<Object[]> targetsWithStatus(@Param("status") String status);

    /**
     * Scans in this status, most recent first, as {@code [id, repoId, containerId]}.
     *
     * <p>Newest first because the caller keeps the first few it may see: taken from
     * {@code findAll()} they were the oldest, so the evidence bundle shipped the twenty earliest
     * attestations of the deployment's life instead of the current ones.
     */
    @Query("""
            select s.id, s.repoId, s.containerId from ScanEntity s
             where s.status = :status
             order by s.createdAt desc, s.id desc""")
    List<Object[]> idsAndTargetsNewestFirst(@Param("status") String status);

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

    /**
     * The identifiers of the scans holding an SBOM, newest first, below a cursor — the pages the
     * inventory's backfill reads. Which of them the inventory has indexed is its own table's to say.
     */
    @Query("select s.id from ScanEntity s where s.sbom is not null and s.id < :before order by s.id desc")
    List<Long> findIdsWithSbomBefore(@Param("before") long before, Limit limit);

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
            select new com.asmolabs.vectispire.core.scanning.persistence.queries.LatestScanRow(
                       s.repoId, s.id, s.status, s.createdAt, s.error)
              from ScanEntity s
             where s.repoId is not null
               and s.id = (select max(l.id) from ScanEntity l where l.repoId = s.repoId)""")
    List<LatestScanRow> findLatestPerRepository();

    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.queries.LatestScanRow(
                       s.containerId, s.id, s.status, s.createdAt, s.error)
              from ScanEntity s
             where s.containerId is not null
               and s.id = (select max(l.id) from ScanEntity l where l.containerId = s.containerId)""")
    List<LatestScanRow> findLatestPerContainer();

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

    /**
     * The most recent scans of the given targets, newest first.
     *
     * <p>The allowance as SQL, so the limit applies after it: filtered in memory after
     * {@link #findHistory}, a restricted reader would have been shown whatever share of the
     * deployment's last few scans happened to be theirs — often none. Neither list may be empty:
     * `in ()` is not valid everywhere, so the caller passes a sentinel.
     */
    @Query("""
            select s from ScanEntity s
             where s.repoId in :repoIds or s.containerId in :containerIds
             order by s.createdAt desc, s.id desc""")
    List<ScanEntity> findRecentWithin(
            @Param("repoIds") java.util.Collection<Long> repoIds,
            @Param("containerIds") java.util.Collection<Long> containerIds,
            Limit limit);

    /**
     * The scans a worker holds <b>and is still renewing</b>: its lease has not lapsed.
     *
     * <p>The complement of {@link #findLapsed}, condition for condition — a null lease counts as
     * lapsed in both, so a scan is never held and reclaimable at the same instant, nor neither.
     */
    @Query("""
            select count(s.id) from ScanEntity s
             where s.status = :status and s.claimedBy = :worker
               and s.leaseExpiresAt is not null and s.leaseExpiresAt >= :asOf""")
    long countHeld(@Param("worker") String worker, @Param("status") String status, @Param("asOf") Instant asOf);

    long countByStatusAndClaimedBy(String status, String claimedBy);

    @Query("""
            select s.claimedBy, count(s.id) from ScanEntity s
             where s.status = :status and s.claimedBy is not null
             group by s.claimedBy""")
    List<Object[]> countRunningByClaimant(@Param("status") String status);

    /**
     * The waiting scans, grouped by the label they require.
     *
     * <p>Only the labelled ones: a scan with no requirement goes to anybody, so counting it here
     * would report as unroutable the work every worker is entitled to take.
     */
    @Query("""
            select s.requiredAgentLabel, count(s.id) from ScanEntity s
             where s.status = :status and s.requiredAgentLabel is not null
             group by s.requiredAgentLabel""")
    List<Object[]> countPendingByRequiredLabel(@Param("status") String status);

    /**
     * The waiting scans of repositories, grouped by the label they require <b>and</b> by repository,
     * as {@code [requiredLabel, repoId, count]}: what the figure of the scans no capable executor can
     * take starts from, since whether a scan needs a credential is its repository's to say.
     *
     * <p>One row per waiting repository and label, so as long as the queue's distinct targets — the
     * scheduler stacks no second scan on a target whose first has not started.
     */
    @Query("""
            select s.requiredAgentLabel, s.repoId, count(s.id) from ScanEntity s
             where s.status = :status and s.repoId is not null
             group by s.requiredAgentLabel, s.repoId""")
    List<Object[]> countPendingByRequiredLabelAndRepository(@Param("status") String status);

    /** The scans of repositories in this status that were counted at least one attempt, as {@code [id, repoId]}. */
    @Query("""
            select s.id, s.repoId from ScanEntity s
             where s.status = :status and s.repoId is not null and s.attempts > 0""")
    List<Object[]> findAttemptedRepositoryScans(@Param("status") String status);

    /**
     * Gives these scans their attempts back, <b>while they are still in this status</b>: one a worker
     * claimed since it was read keeps the attempt that claim counted.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ScanEntity s set s.attempts = 0 where s.id in :ids and s.status = :status and s.attempts > 0")
    int resetAttempts(@Param("ids") Collection<Long> ids, @Param("status") String status);

    @Query("select s.id from ScanEntity s where s.containerId = :containerId")
    List<Long> findIdsByContainerId(@Param("containerId") Long containerId);

    @Query("select s.id from ScanEntity s where s.repoId = :repoId")
    List<Long> findIdsByRepoId(@Param("repoId") Long repoId);

    @Query("""
            select s.id from ScanEntity s
             where (s.containerId is not null and s.containerId not in (select c.id from ContainerEntity c))
                or (s.repoId is not null and s.repoId not in (select r.id from RepositoryEntity r))""")
    List<Long> findOrphanedIds();

    /**
     * Deletes in one statement, <b>after flushing what the persistence context still holds</b>.
     *
     * <p>The purge before it removes the components, AI reviews and findings through Spring Data's derived deletes, which load
     * each row and queue its removal until the next flush. Executed straight away, this statement
     * took the parents first, the schema's cascade took the children with them, and the queued
     * removals then found nothing at commit: an optimistic-locking failure, and a target that could
     * not be deleted once anybody had triaged one of its findings. Found by {@code
     * TargetDeletionTest} on 2026-09-26; the deletion service had carried it since it was written.
     *
     * <p>{@code @Transactional} was missing too, against the rule in {@code package-info}: its one
     * caller always held a transaction, which is exactly how the omission survives review.
     */
    @Transactional
    @Modifying(flushAutomatically = true)
    @Query("delete from ScanEntity s where s.id in :ids")
    void deleteByIdIn(@Param("ids") Collection<Long> ids);

    /**
     * Whether one target has ever completed a scan.
     *
     * <p><b>A boolean asked as a boolean.</b> The scorecard used to answer this with
     * {@code findAll().stream().anyMatch(...)} — every scan row in the deployment loaded and
     * discarded, on a path served per page view — because the question reads naturally in Java
     * and the cost only shows up on somebody else's data.
     */
    boolean existsByRepoIdAndStatusIgnoreCase(Long repoId, String status);

    /** The container half of {@link #existsByRepoIdAndStatusIgnoreCase}. */
    boolean existsByContainerIdAndStatusIgnoreCase(Long containerId, String status);

    /**
     * One target's scans.
     *
     * <p>Added for the licence inventory, which read every scan in the deployment — and a scan
     * row carries its whole SBOM payload, megabytes of JSON apiece. Asking for one repository's
     * licences parsed the estate's.
     */
    List<ScanEntity> findByRepoId(Long repoId);

    List<ScanEntity> findByContainerId(Long containerId);

    List<ScanEntity> findByStatusInOrderByCreatedAtAsc(Collection<String> statuses);

    long countByStatusAndCreatedAtAfter(String status, Instant after);

    @Query("select avg(s.durationMs) from ScanEntity s where s.status = :status and s.createdAt >= :after and s.durationMs is not null")
    Double findAvgDurationMsByStatusAndCreatedAtAfter(@Param("status") String status, @Param("after") Instant after);

    /**
     * The identifiers of a repository's recent scans, newest first.
     *
     * <p><b>Identifiers, not entities.</b> The SBOM comparison called {@code findAll()} and then
     * filtered and kept two rows in Java: every scan row in the deployment loaded to retain two
     * identifiers — and a scan row carries its whole SBOM payload, megabytes apiece, as
     * {@link #findByRepoId(Long)} already says a little above. Comparing two scans of one
     * repository therefore read the SBOMs of the entire estate.
     *
     * <p>The projection onto {@code s.id} is half the fix; the bound is the other. Together they
     * make the cost of this read independent of the history.
     */
    @Query("select s.id from ScanEntity s where s.repoId = :repoId order by s.id desc")
    List<Long> findRecentIdsByRepoId(@Param("repoId") Long repoId, Limit limit);

    /** The container half of {@link #findRecentIdsByRepoId}. */
    @Query("select s.id from ScanEntity s where s.containerId = :containerId order by s.id desc")
    List<Long> findRecentIdsByContainerId(@Param("containerId") Long containerId, Limit limit);

    /**
     * The next completed scan of the same target, which closes the window an earlier scan's gate
     * verdict can belong to. Two queries rather than one on a nullable column: `repo_id = null`
     * matches nothing in SQL, and the caller knows which kind of target it holds.
     */
    java.util.Optional<ScanEntity> findFirstByRepoIdAndStatusAndCreatedAtGreaterThanOrderByCreatedAtAsc(
            Long repoId, String status, Instant after);

    java.util.Optional<ScanEntity> findFirstByContainerIdAndStatusAndCreatedAtGreaterThanOrderByCreatedAtAsc(
            Long containerId, String status, Instant after);
}
