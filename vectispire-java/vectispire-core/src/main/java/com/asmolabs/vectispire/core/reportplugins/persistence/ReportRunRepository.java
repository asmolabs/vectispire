package com.asmolabs.vectispire.core.reportplugins.persistence;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The report runs, and their queue — the scan queue's pattern, not a mechanism of its own.
 *
 * <p><b>The claim is a read, then a conditional update per candidate, with no row lock</b>, as {@code
 * ScanQueue.takeBatch} settled for scans: the waiting runs are read oldest first, and each is taken by an
 * update that names the state it expects; of two executors racing on one row the database lets exactly one
 * update match, and the other moves on. <b>Every write after the take names its owner</b> — the run's state
 * and the executor that took it — so that an executor whose lease lapsed, and whose run was failed as lost,
 * writes nothing over what was decided without it.
 */
public interface ReportRunRepository extends JpaRepository<ReportRunEntity, Long> {

    /** The waiting runs, oldest first — the candidates of a claim. */
    @Query("select r.id from ReportRunEntity r where r.state = :pending order by r.requestedAt asc, r.id asc")
    List<Long> waiting(@Param("pending") String pending, Pageable page);

    /**
     * Takes one waiting run, and says whether it was still there to take: 1 for the executor whose update
     * matched, 0 for any other.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ReportRunEntity r
               set r.state = :running, r.claimedBy = :owner, r.startedAt = :startedAt,
                   r.leaseExpiresAt = :leaseExpiresAt
             where r.id = :id and r.state = :pending""")
    int take(
            @Param("id") long id,
            @Param("pending") String pending,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("startedAt") Instant startedAt,
            @Param("leaseExpiresAt") Instant leaseExpiresAt);

    /**
     * Extends the lease of a run its owner still holds, and says whether it did: 0 once the run ended, or was
     * failed as lost, or is another executor's — a renewal names its claimant like every write after the take,
     * so one executor's heartbeat never keeps another's run alive.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ReportRunEntity r set r.leaseExpiresAt = :leaseExpiresAt
             where r.id = :id and r.state = :running and r.claimedBy = :owner""")
    int renew(
            @Param("id") long id,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("leaseExpiresAt") Instant leaseExpiresAt);

    /** The runs whose executor stopped answering: running, their lease lapsed. */
    @Query("select r.id from ReportRunEntity r where r.state = :running and r.leaseExpiresAt < :asOf order by r.id")
    List<Long> lapsed(@Param("running") String running, @Param("asOf") Instant asOf);

    /**
     * Ends a run its owner still holds, with everything the run learnt — or nothing, when the owner no longer
     * holds it. The active key goes with the lease: the next request for the plugin and the project may queue.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ReportRunEntity r
               set r.state = :state, r.reason = :reason, r.detail = :detail, r.finishedAt = :finishedAt,
                   r.activeKey = null, r.claimedBy = null, r.leaseExpiresAt = null,
                   r.projectName = :projectName, r.exportedAt = :exportedAt,
                   r.manifestDigest = :manifestDigest, r.imageDigest = :imageDigest,
                   r.signerIdentity = :signerIdentity, r.signerIssuer = :signerIssuer,
                   r.signerKeySha256 = :signerKeySha256, r.exportSchemaVersion = :exportSchemaVersion,
                   r.exportSha256 = :exportSha256, r.exportSize = :exportSize, r.exitCode = :exitCode,
                   r.outputSize = :outputSize, r.outputSha256 = :outputSha256, r.productVersion = :productVersion,
                   r.outputMediaType = :outputMediaType, r.signingKeyId = :signingKeyId,
                   r.packageSha256 = :packageSha256
             where r.id = :id and r.state = :running and r.claimedBy = :owner""")
    int finish(
            @Param("id") long id,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("state") String state,
            @Param("reason") String reason,
            @Param("detail") String detail,
            @Param("finishedAt") Instant finishedAt,
            @Param("projectName") String projectName,
            @Param("exportedAt") Instant exportedAt,
            @Param("manifestDigest") String manifestDigest,
            @Param("imageDigest") String imageDigest,
            @Param("signerIdentity") String signerIdentity,
            @Param("signerIssuer") String signerIssuer,
            @Param("signerKeySha256") String signerKeySha256,
            @Param("exportSchemaVersion") String exportSchemaVersion,
            @Param("exportSha256") String exportSha256,
            @Param("exportSize") Long exportSize,
            @Param("exitCode") Integer exitCode,
            @Param("outputSize") Long outputSize,
            @Param("outputSha256") String outputSha256,
            @Param("productVersion") String productVersion,
            @Param("outputMediaType") String outputMediaType,
            @Param("signingKeyId") String signingKeyId,
            @Param("packageSha256") String packageSha256);

    /**
     * Fails a run whose lease lapsed — and only while it still has: an executor that came back and finished it
     * in between keeps what it wrote.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ReportRunEntity r
               set r.state = :failed, r.reason = :reason, r.detail = :detail, r.finishedAt = :asOf,
                   r.activeKey = null, r.claimedBy = null, r.leaseExpiresAt = null
             where r.id = :id and r.state = :running and r.leaseExpiresAt < :asOf""")
    int failLapsed(
            @Param("id") long id,
            @Param("running") String running,
            @Param("failed") String failed,
            @Param("reason") String reason,
            @Param("detail") String detail,
            @Param("asOf") Instant asOf);

    /**
     * Whether any executor is at work, or was lately — the runs running, or started after {@code since}; none
     * means none. An
     * executor that is there claims a waiting run within its interval, and one too busy to has runs in hand.
     */
    @Query("select count(r) from ReportRunEntity r where r.state = :running or r.startedAt > :since")
    long executorsSeenSince(@Param("running") String running, @Param("since") Instant since);

    /** The runs still waiting that were asked before {@code before}. */
    @Query("select r.id from ReportRunEntity r where r.state = :pending and r.requestedAt < :before order by r.id")
    List<Long> unclaimed(@Param("pending") String pending, @Param("before") Instant before);

    /**
     * Fails a run nobody claimed — and only while nobody has: a take that won the race keeps the run.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ReportRunEntity r
               set r.state = :failed, r.reason = :reason, r.detail = :detail, r.finishedAt = :asOf,
                   r.activeKey = null
             where r.id = :id and r.state = :pending""")
    int failUnclaimed(
            @Param("id") long id,
            @Param("pending") String pending,
            @Param("failed") String failed,
            @Param("reason") String reason,
            @Param("detail") String detail,
            @Param("asOf") Instant asOf);

    /** Whether a run of this plugin for this project is pending or running — what the active key holds. */
    boolean existsByActiveKey(String activeKey);

    Optional<ReportRunEntity> findByActiveKey(String activeKey);

    /** A project's runs, newest first, a page at a time. */
    List<ReportRunEntity> findByProjectIdOrderByRequestedAtDescIdDesc(long projectId, Pageable page);

    Optional<ReportRunEntity> findByIdAndProjectId(long id, long projectId);

    /** Every run of a project that is going away — its listener's, in the deleting transaction. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ReportRunEntity r where r.projectId = :projectId")
    int deleteByProject(@Param("projectId") long projectId);
}
