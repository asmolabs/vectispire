package com.asmolabs.vectispire.core.scanning.persistence;

import com.asmolabs.vectispire.core.scanning.persistence.queries.ExaminingScanRow;
import com.asmolabs.vectispire.core.scanning.persistence.queries.LatestScanRow;
import com.asmolabs.vectispire.core.scanning.persistence.queries.NewestCompletedScanRow;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The scan queue, whose claim is the whole point.
 *
 * <p><b>The claim is a read, then a conditional update per candidate, with no row lock</b> — see
 * {@code ScanQueue.takeBatch} for why {@code SELECT … FOR UPDATE SKIP LOCKED} was dropped, and what it
 * cost on MySQL. The two queries that locked were kept after nothing called them; they are gone,
 * since a claim written against them would have skipped none of the rules below.
 *
 * <p><b>The routing filter lives inside the selection, never after it</b>, and so does the wait a
 * failed attempt earns ({@code notBefore}): every selection and the take itself say "due by
 * {@code :asOf}", the take too because a scan may fail and be requeued with a wait between the read
 * that offered it and the update that takes it.
 *
 * <p><b>Ask for exactly what is needed, and retry.</b> The obvious idea — take a wider window
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
     * How many scans of this target are waiting or running.
     *
     * <p>The scheduler's question, wider than the button's: a target whose scan is under way when its
     * round comes needs no second one queued behind it — the one running is the round. The button
     * still queues behind a running scan, because whoever presses it may have just pushed the fix.
     */
    long countByStatusInAndRepoId(Collection<String> statuses, Long repoId);

    long countByStatusInAndContainerId(Collection<String> statuses, Long containerId);

    /**
     * The scans this claimant may take, due by {@code asOf}, in claim order.
     *
     * <p>Paired with {@link #take}: the candidates are read, then each is taken by a
     * conditional update whose {@code where} still says {@code pending}. A row somebody else
     * took in between updates zero rows and drops out of the batch.
     *
     * @param labels the agent's capabilities; a scan requiring none goes to anyone
     * @param asOf the claim's instant: a scan whose {@code notBefore} is later waits
     */
    @Query("""
            select s from ScanEntity s
             where s.status = :status
               and (s.requiredAgentLabel is null or s.requiredAgentLabel in :labels)
               and (s.notBefore is null or s.notBefore <= :asOf)
             order by s.createdAt asc, s.id asc""")
    List<ScanEntity> findClaimable(
            @Param("status") String status,
            @Param("labels") Collection<String> labels,
            @Param("asOf") Instant asOf,
            Limit limit);

    /**
     * The same query for an agent that carries no label at all.
     *
     * <p>Written out rather than passing an empty collection: {@code in ()} is a syntax error on
     * several engines, and the usual workaround — a sentinel value nothing equals — is a magic
     * string that has to stay impossible forever. It also stopped being impossible the moment it
     * contained a NUL byte, which PostgreSQL refuses outright.
     */
    @Query("""
            select s from ScanEntity s
             where s.status = :status and s.requiredAgentLabel is null
               and (s.notBefore is null or s.notBefore <= :asOf)
             order by s.createdAt asc, s.id asc""")
    List<ScanEntity> findClaimableUnlabelled(@Param("status") String status, @Param("asOf") Instant asOf, Limit limit);

    /**
     * How many waiting scans are due by {@code asOf}, whatever they require — what tells the claim's
     * loop that another turn cannot find anything.
     */
    @Query("""
            select count(s.id) from ScanEntity s
             where s.status = :status
               and (s.notBefore is null or s.notBefore <= :asOf)""")
    long countDue(@Param("status") String status, @Param("asOf") Instant asOf);

    /**
     * The claimable selection in claim order, a page at a time, for an agent that cannot be handed a
     * delegated credential (decision 0031) — see {@code ScanQueue.claimWithin}.
     *
     * <p><b>A page of columns, not a list of exclusions.</b> This used to be the same selection with
     * {@code and s.repoId not in :excluded}, the list being every waiting repository that carries a
     * credential: bounded by nothing but the queue, and one bind parameter per repository. Past the
     * engines' limits — 65,535 for the PostgreSQL driver and a MySQL server-side statement — the claim
     * itself failed, at every poll of every such agent. The caller
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
               and (s.notBefore is null or s.notBefore <= :asOf)
             order by s.createdAt asc, s.id asc""")
    List<ClaimCandidate> findClaimablePage(
            @Param("status") String status,
            @Param("labels") Collection<String> labels,
            @Param("asOf") Instant asOf,
            Limit limit);

    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.ClaimCandidate(s.id, s.repoId, s.createdAt)
              from ScanEntity s
             where s.status = :status
               and (s.requiredAgentLabel is null or s.requiredAgentLabel in :labels)
               and (s.notBefore is null or s.notBefore <= :asOf)
               and (s.createdAt > :afterAt or (s.createdAt = :afterAt and s.id > :afterId))
             order by s.createdAt asc, s.id asc""")
    List<ClaimCandidate> findClaimablePageAfter(
            @Param("status") String status,
            @Param("labels") Collection<String> labels,
            @Param("asOf") Instant asOf,
            @Param("afterAt") Instant afterAt,
            @Param("afterId") Long afterId,
            Limit limit);

    /** The two pages for an agent that carries no label — {@code in ()} is not valid everywhere. */
    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.ClaimCandidate(s.id, s.repoId, s.createdAt)
              from ScanEntity s
             where s.status = :status and s.requiredAgentLabel is null
               and (s.notBefore is null or s.notBefore <= :asOf)
             order by s.createdAt asc, s.id asc""")
    List<ClaimCandidate> findClaimableUnlabelledPage(
            @Param("status") String status, @Param("asOf") Instant asOf, Limit limit);

    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.ClaimCandidate(s.id, s.repoId, s.createdAt)
              from ScanEntity s
             where s.status = :status and s.requiredAgentLabel is null
               and (s.notBefore is null or s.notBefore <= :asOf)
               and (s.createdAt > :afterAt or (s.createdAt = :afterAt and s.id > :afterId))
             order by s.createdAt asc, s.id asc""")
    List<ClaimCandidate> findClaimableUnlabelledPageAfter(
            @Param("status") String status,
            @Param("asOf") Instant asOf,
            @Param("afterAt") Instant afterAt,
            @Param("afterId") Long afterId,
            Limit limit);

    /**
     * Takes one row, and says whether it was still there to take.
     *
     * <p>{@code status = :from} in the {@code where} is what makes this safe without a lock:
     * two claimants racing on the same row both issue the update, and exactly one of them
     * changes a row.
     *
     * <p><b>The wait is in the {@code where} too</b>, not only in the read that offered the row: in
     * between, the scan may have been taken, failed and requeued with a wait, by another executor —
     * still {@code pending}, and not due. The take clears it: a running scan waits for nothing.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s
               set s.status = :to, s.claimedBy = :worker, s.claimedAt = :claimedAt,
                   s.leaseExpiresAt = :leaseExpiresAt, s.attempts = s.attempts + 1, s.notBefore = null
             where s.id = :id and s.status = :from
               and (s.notBefore is null or s.notBefore <= :claimedAt)""")
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
                   s.claimedAt = null, s.leaseExpiresAt = null, s.notBefore = null
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
     *
     * @param notBefore when the scan becomes claimable again; null when it failed for good
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s
               set s.status = :to, s.error = :error, s.claimedBy = null,
                   s.claimedAt = null, s.leaseExpiresAt = null, s.notBefore = :notBefore
             where s.id = :id and s.status = :running and s.claimedBy = :owner and s.attempts = :attempt""")
    int releaseOwnedAttempt(
            @Param("id") Long id,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("attempt") int attempt,
            @Param("to") String to,
            @Param("error") String error,
            @Param("notBefore") Instant notBefore);

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
                   s.claimedAt = null, s.leaseExpiresAt = null, s.notBefore = null,
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
     *
     * @param notBefore when a requeued scan becomes claimable again — a lapse is a transient failure
     *     and waits as a reported one does; null for one failed for good
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s
               set s.status = :to, s.error = :error, s.claimedBy = null,
                   s.claimedAt = null, s.leaseExpiresAt = null, s.notBefore = :notBefore
             where s.id = :id and s.status = :running
               and (s.leaseExpiresAt is null or s.leaseExpiresAt < :asOf)""")
    int releaseLapsed(
            @Param("id") Long id,
            @Param("running") String running,
            @Param("asOf") Instant asOf,
            @Param("to") String to,
            @Param("error") String error,
            @Param("notBefore") Instant notBefore);

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
     * Each of these repositories' newest scan with this status, created at or after {@code since},
     * whose {@code examined_types} holds the type {@code pattern} matches — see {@code
     * ExaminedTypes.pattern}.
     *
     * <p><b>The list wrapped in commas, then {@code like}.</b> The engines share no function that
     * splits a column, and a JSON one would be three spellings of one query; a comma on each side
     * makes {@code sast} match {@code ,iac,sast,} and never a name containing it. A null column —
     * unrecorded — concatenates to null on every engine, and matches nothing.
     *
     * <p>The newest is the highest identifier, as for {@link #findLatestPerRepository}: two scans of
     * one repository created in the same instant would otherwise both be its newest.
     *
     * <p>{@code repoIds} binds one parameter per element: the caller hands at most a thousand.
     */
    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.queries.ExaminingScanRow(
                       s.repoId, s.id, s.createdAt, case when s.sbom is null then false else true end)
              from ScanEntity s
             where s.repoId in :repoIds
               and s.id = (select max(l.id) from ScanEntity l
                            where l.repoId = s.repoId
                              and l.status = :status
                              and l.createdAt >= :since
                              and concat(',', l.examinedTypes, ',') like :pattern)""")
    List<ExaminingScanRow> findNewestExamining(
            @Param("repoIds") Collection<Long> repoIds,
            @Param("status") String status,
            @Param("since") Instant since,
            @Param("pattern") String pattern);

    /**
     * Each of these scans' id, branch and project version. A scan that does not exist is absent.
     *
     * <p>{@code ids} binds one parameter per element: the caller hands at most a thousand.
     */
    @Query("select s.id, s.branch, s.version from ScanEntity s where s.id in :ids")
    List<Object[]> findLabelsOf(@Param("ids") Collection<Long> ids);

    /**
     * Each of these scans' id, the languages its census found and the languages its Semgrep rules
     * read, each null where the scan recorded none. A scan that does not exist is absent.
     *
     * <p>{@code ids} binds one parameter per element: the caller hands at most a thousand.
     */
    @Query("select s.id, s.detectedLanguages, s.sastLanguages from ScanEntity s where s.id in :ids")
    List<Object[]> findLanguagesOf(@Param("ids") Collection<Long> ids);

    /**
     * Each of these scans' id, queuing instant, duration, examined types, failure summary and plugin
     * steps — a scan as a document describes it, without the SBOM and the CVE list every whole row
     * carries. A scan that does not exist is absent.
     *
     * <p>{@code ids} binds one parameter per element: the caller hands at most a thousand.
     */
    @Query("""
            select s.id, s.createdAt, s.durationMs, s.examinedTypes, s.error, s.pluginSteps
              from ScanEntity s where s.id in :ids""")
    List<Object[]> findOutlinesOf(@Param("ids") Collection<Long> ids);

    /**
     * Records the languages the Semgrep rules of a scan's task read, when the task is built — null for a
     * task without the SAST step.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ScanEntity s set s.sastLanguages = :languages where s.id = :id")
    int recordSastLanguages(@Param("id") long id, @Param("languages") String languages);

    /**
     * Per repository, its newest scan with this status (the highest id), and whether that scan still
     * holds its SBOM. A repository with no such scan is absent.
     *
     * <p>{@code repoIds} binds one parameter per element: the caller hands at most a thousand.
     */
    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.queries.NewestCompletedScanRow(
                       s.repoId, s.containerId, s.id, s.createdAt, case when s.sbom is null then false else true end)
              from ScanEntity s
             where s.repoId in :repoIds
               and s.id = (select max(l.id) from ScanEntity l
                            where l.repoId = s.repoId
                              and l.status = :status)""")
    List<NewestCompletedScanRow> findNewestWithStatusOfRepositories(
            @Param("repoIds") Collection<Long> repoIds,
            @Param("status") String status);

    /** The same, per image: {@code containerIds} one parameter each, a thousand at most. */
    @Query("""
            select new com.asmolabs.vectispire.core.scanning.persistence.queries.NewestCompletedScanRow(
                       s.repoId, s.containerId, s.id, s.createdAt, case when s.sbom is null then false else true end)
              from ScanEntity s
             where s.containerId in :containerIds
               and s.id = (select max(l.id) from ScanEntity l
                            where l.containerId = s.containerId
                              and l.status = :status)""")
    List<NewestCompletedScanRow> findNewestWithStatusOfContainers(
            @Param("containerIds") Collection<Long> containerIds,
            @Param("status") String status);

    /**
     * Per repository, its newest scan with this status (the highest id) and the languages that scan's
     * census recorded — null when it recorded none. A repository with no such scan is absent.
     *
     * <p>{@code repoIds} binds one parameter per element: the caller hands at most a thousand.
     */
    @Query("""
            select s.repoId, s.detectedLanguages
              from ScanEntity s
             where s.repoId in :repoIds
               and s.id = (select max(l.id) from ScanEntity l
                            where l.repoId = s.repoId
                              and l.status = :status)""")
    List<Object[]> findNewestDetectedLanguages(
            @Param("repoIds") Collection<Long> repoIds,
            @Param("status") String status);

    /**
     * Per repository, its scans with this status created at or after {@code since}, and how many of
     * them hold no {@code examined_types} — scans from before the record, which say nothing of whether
     * a step ran (decision 0032, §6). A repository with no such scan is absent from the answer.
     *
     * <p>{@code repoIds} binds one parameter per element: the caller hands at most a thousand.
     */
    @Query("""
            select s.repoId, count(s.id), sum(case when s.examinedTypes is null then 1 else 0 end)
              from ScanEntity s
             where s.repoId in :repoIds and s.status = :status and s.createdAt >= :since
             group by s.repoId""")
    List<Object[]> countScansWithin(
            @Param("repoIds") Collection<Long> repoIds, @Param("status") String status, @Param("since") Instant since);

    /**
     * The scans with this status created at or after {@code since} whose {@code plugin_steps} names a
     * plugin — {@code pattern} is {@code %"pluginId":"<id>"%}, which a plugin id's own characters (lowercase
     * letters, digits, inner hyphens) cannot escape — with the column, for the caller to read the
     * plugin's state. Newest first within a repository.
     *
     * <p>{@code repoIds} binds one parameter per element: the caller hands at most a thousand.
     */
    @Query("""
            select s.repoId, s.id, s.createdAt, s.pluginSteps
              from ScanEntity s
             where s.repoId in :repoIds and s.status = :status and s.createdAt >= :since
               and s.pluginSteps like :pattern
             order by s.repoId asc, s.id desc""")
    List<Object[]> findNamingPluginWithin(
            @Param("repoIds") Collection<Long> repoIds,
            @Param("status") String status,
            @Param("since") Instant since,
            @Param("pattern") String pattern);

    /** The repositories among these with a scan of this status before {@code before} naming the plugin. */
    @Query("""
            select distinct s.repoId
              from ScanEntity s
             where s.repoId in :repoIds and s.status = :status and s.createdAt < :before
               and s.pluginSteps like :pattern""")
    List<Long> findNamingPluginBefore(
            @Param("repoIds") Collection<Long> repoIds,
            @Param("status") String status,
            @Param("before") Instant before,
            @Param("pattern") String pattern);

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
     *
     * <p>Both lists bind one parameter per element: {@code ScanCatalog.recentWithin} hands at most a
     * thousand and merges the batches' newest.
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
     *
     * <p><b>And the wait those attempts earned.</b> The wait is the price of the attempts counted: a
     * scan whose count is back at zero waiting five minutes for its "third" attempt would be a scan
     * the queue holds back for a failure it no longer counts.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ScanEntity s set s.attempts = 0, s.notBefore = null
             where s.id in :ids and s.status = :status and s.attempts > 0""")
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
     * Every scan's identifier, targets and SBOM, as {@code [id, repoId, containerId, sbom]} — what the
     * licence inventory reads of a scan, and nothing else of the row.
     *
     * <p><b>Not the entities.</b> The inventory read whole rows: the CVE list, the summary and the plugin
     * steps came along with the SBOM it parses, each a document of its own, and every row entered the
     * persistence context to be dropped at once. A scan row carries its whole SBOM payload, megabytes
     * of JSON apiece, so the read is still the history's — what the estate's inventory is made of.
     */
    @Query("select s.id, s.repoId, s.containerId, s.sbom from ScanEntity s")
    List<Object[]> sbomsOfAll();

    /** {@link #sbomsOfAll()} for the scans naming one of these repositories. */
    @Query("select s.id, s.repoId, s.containerId, s.sbom from ScanEntity s where s.repoId in :repoIds")
    List<Object[]> sbomsOfRepositories(@Param("repoIds") Collection<Long> repoIds);

    /** {@link #sbomsOfAll()} for the scans naming one of these images. */
    @Query("select s.id, s.repoId, s.containerId, s.sbom from ScanEntity s where s.containerId in :containerIds")
    List<Object[]> sbomsOfContainers(@Param("containerIds") Collection<Long> containerIds);

    /** {@link #sbomsOfAll()} for the scans attached to no target. */
    @Query("select s.id, s.repoId, s.containerId, s.sbom from ScanEntity s where s.repoId is null and s.containerId is null")
    List<Object[]> sbomsOfUntargeted();

    /**
     * How the scans of each target stand, as {@code [repoId, containerId, status, scans, newest id,
     * scans holding an SBOM]} per target and status.
     *
     * <p>Columns and counts only: what the licence tallies compare to decide whether a target's
     * inventory can have moved, without reading the payloads the inventory is made of. Whether the
     * SBOM is null is read off the row, not off the document.
     */
    @Query("""
            select s.repoId, s.containerId, s.status, count(s.id), max(s.id),
                   sum(case when s.sbom is not null then 1 else 0 end)
              from ScanEntity s
             group by s.repoId, s.containerId, s.status""")
    List<Object[]> censusByTargetAndStatus();

    /** The scans holding an SBOM, as {@code [id, repoId, containerId]}, without the SBOM. */
    @Query("select s.id, s.repoId, s.containerId from ScanEntity s where s.sbom is not null")
    List<Object[]> idsAndTargetsWithSbom();

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
     * {@link #sbomsOfAll()} already says a little above. Comparing two scans of one
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
