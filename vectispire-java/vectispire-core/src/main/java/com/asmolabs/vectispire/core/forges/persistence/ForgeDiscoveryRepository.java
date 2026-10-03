package com.asmolabs.vectispire.core.forges.persistence;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The discoveries, and their queue — the scan queue's pattern, not a mechanism of its own.
 *
 * <p><b>The claim is a read, then a conditional update per candidate, with no row lock</b>: the waiting runs are
 * read oldest first, and each is taken by an update naming the state it expects; of two instances racing on one
 * row the database lets exactly one update match. <b>Every write after the take names its owner</b> — the run's
 * state and the instance that took it — so that an instance whose lease lapsed, and whose run was given to
 * another, writes nothing over the other's progress.
 */
public interface ForgeDiscoveryRepository extends JpaRepository<ForgeDiscoveryEntity, Long> {

    /** The waiting runs, oldest first — the candidates of a claim. */
    @Query("select d.id from ForgeDiscoveryEntity d where d.state = :pending order by d.requestedAt asc, d.id asc")
    List<Long> waiting(@Param("pending") String pending, Pageable page);

    /**
     * Takes one waiting run, counts the attempt and starts its progress afresh — a resumed run lists again from
     * the first page: 1 for the instance whose update matched, 0 for any other.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ForgeDiscoveryEntity d
               set d.state = :running, d.claimedBy = :owner, d.leaseExpiresAt = :leaseExpiresAt,
                   d.startedAt = :startedAt, d.attempts = d.attempts + 1,
                   d.namespacesSeen = 0, d.repositoriesSeen = 0, d.repositoriesSkipped = 0, d.requestsMade = 0,
                   d.rateLimitWaitSeconds = 0
             where d.id = :id and d.state = :pending""")
    int take(
            @Param("id") long id,
            @Param("pending") String pending,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("startedAt") Instant startedAt,
            @Param("leaseExpiresAt") Instant leaseExpiresAt);

    /**
     * Writes the progress and extends the lease of a run its owner still holds: 0 when it no longer does — the
     * lease lapsed and the run was given to another, or the connection was deleted with its runs.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ForgeDiscoveryEntity d
               set d.leaseExpiresAt = :leaseExpiresAt, d.namespacesSeen = :namespaces,
                   d.repositoriesSeen = :repositories, d.repositoriesSkipped = :skipped, d.requestsMade = :requests,
                   d.rateLimitWaitSeconds = :waited
             where d.id = :id and d.state = :running and d.claimedBy = :owner""")
    int renew(
            @Param("id") long id,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("leaseExpiresAt") Instant leaseExpiresAt,
            @Param("namespaces") int namespaces,
            @Param("repositories") int repositories,
            @Param("skipped") int skipped,
            @Param("requests") int requests,
            @Param("waited") long waited);

    /** Ends a run its owner still holds, with what it learnt; the active key goes with the lease. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ForgeDiscoveryEntity d
               set d.state = :state, d.reason = :reason, d.detail = :detail, d.finishedAt = :finishedAt,
                   d.activeKey = null, d.claimedBy = null, d.leaseExpiresAt = null,
                   d.namespacesSeen = :namespaces, d.repositoriesSeen = :repositories,
                   d.repositoriesSkipped = :skipped, d.requestsMade = :requests, d.rateLimitWaitSeconds = :waited,
                   d.rateLimitResetAt = :resetAt, d.newCount = :newCount, d.changedCount = :changedCount,
                   d.goneCount = :goneCount, d.unreadableNamespaces = :unreadable
             where d.id = :id and d.state = :running and d.claimedBy = :owner""")
    int finish(
            @Param("id") long id,
            @Param("running") String running,
            @Param("owner") String owner,
            @Param("state") String state,
            @Param("reason") String reason,
            @Param("detail") String detail,
            @Param("finishedAt") Instant finishedAt,
            @Param("namespaces") int namespaces,
            @Param("repositories") int repositories,
            @Param("skipped") int skipped,
            @Param("requests") int requests,
            @Param("waited") long waited,
            @Param("resetAt") Instant resetAt,
            @Param("newCount") Integer newCount,
            @Param("changedCount") Integer changedCount,
            @Param("goneCount") Integer goneCount,
            @Param("unreadable") String unreadableNamespaces);

    /** The runs whose instance stopped answering: running, their lease lapsed. */
    @Query("select d.id from ForgeDiscoveryEntity d where d.state = :running and d.leaseExpiresAt < :asOf order by d.id")
    List<Long> lapsed(@Param("running") String running, @Param("asOf") Instant asOf);

    /** Puts a lapsed run back to waiting — while it still is lapsed, and has attempts left. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ForgeDiscoveryEntity d
               set d.state = :pending, d.claimedBy = null, d.leaseExpiresAt = null
             where d.id = :id and d.state = :running and d.leaseExpiresAt < :asOf and d.attempts < :maxAttempts""")
    int requeueLapsed(
            @Param("id") long id,
            @Param("running") String running,
            @Param("pending") String pending,
            @Param("asOf") Instant asOf,
            @Param("maxAttempts") int maxAttempts);

    /** Fails a lapsed run that has spent its attempts. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ForgeDiscoveryEntity d
               set d.state = :failed, d.reason = :reason, d.detail = :detail, d.finishedAt = :asOf,
                   d.activeKey = null, d.claimedBy = null, d.leaseExpiresAt = null
             where d.id = :id and d.state = :running and d.leaseExpiresAt < :asOf and d.attempts >= :maxAttempts""")
    int failLapsed(
            @Param("id") long id,
            @Param("running") String running,
            @Param("failed") String failed,
            @Param("reason") String reason,
            @Param("detail") String detail,
            @Param("asOf") Instant asOf,
            @Param("maxAttempts") int maxAttempts);

    Optional<ForgeDiscoveryEntity> findByActiveKey(String activeKey);

    /** A connection's runs, newest first, a page at a time. */
    List<ForgeDiscoveryEntity> findByConnectionIdOrderByRequestedAtDescIdDesc(UUID connectionId, Pageable page);

    Optional<ForgeDiscoveryEntity> findFirstByConnectionIdOrderByRequestedAtDescIdDesc(UUID connectionId);

    Optional<ForgeDiscoveryEntity> findByIdAndConnectionId(long id, UUID connectionId);

    /** The connection's latest discovery in one of these states — the one a selection reads (decision 0037 §4). */
    Optional<ForgeDiscoveryEntity> findFirstByConnectionIdAndStateInOrderByRequestedAtDescIdDesc(
            UUID connectionId, Collection<String> states);

    /**
     * Every run of a connection that is going away. First of the connection's deletions: it waits on the row a
     * running page holds, so that the snapshot's deletion, which follows, sees that page's rows.
     */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ForgeDiscoveryEntity d where d.connectionId = :connectionId")
    int deleteByConnection(@Param("connectionId") UUID connectionId);
}
