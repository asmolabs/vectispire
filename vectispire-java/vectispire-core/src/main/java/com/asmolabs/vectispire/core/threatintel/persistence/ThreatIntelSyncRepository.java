package com.asmolabs.vectispire.core.threatintel.persistence;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface ThreatIntelSyncRepository extends JpaRepository<ThreatIntelSyncEntity, Long> {

    /**
     * Marks an attempt on the row, and so takes the row's write lock until the caller's transaction
     * ends.
     *
     * <p><b>An update rather than a {@code select … for update}</b>: either takes the row's lock on
     * PostgreSQL and MySQL, and the update was chosen while the SQLite fixture, which has no row lock
     * to ask for, was among the engines; it also records the attempt the row exists to show. Two synchronisations writing at once
     * — the schedule on one instance, a lead's button on another — would otherwise both read an issue
     * as not yet exploited and both announce it to the SIEM; the second one now waits, then reads the
     * first one's flags.
     *
     * @return 0 when the row is missing, which the caller creates
     */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ThreatIntelSyncEntity s set s.lastAttemptAt = :at where s.id = :id")
    int markAttempt(@Param("id") long id, @Param("at") Instant at);

    /**
     * Takes the row's write lock until the caller's transaction ends, and changes nothing: the first
     * statement of each page of the KEV re-evaluation.
     *
     * <p><b>Why each page takes it.</b> The re-evaluation is a page of open issues per transaction,
     * and a newly flagged issue is announced to the SIEM in the page that flags it. Two
     * synchronisations walking the backlog at once — the schedule on one instance, a lead's button on
     * another — would each read an issue as not yet exploited and each announce it. Under the lock the
     * second one's page waits for the first one's to commit, and only then reads the flags: on
     * PostgreSQL a statement's snapshot is taken when it starts, and on MySQL a transaction's at its
     * first plain read, which comes after this update — so the flags read are the ones just committed.
     * The column set to itself because an update is the lock every engine has (see {@link
     * #markAttempt}), and it must not move the attempt the schedule's retry is timed from.
     */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ThreatIntelSyncEntity s set s.lastAttemptAt = s.lastAttemptAt where s.id = :id")
    int holdForReevaluation(@Param("id") long id);

    /**
     * Claims the scheduled synchronisation for this instance, if one is due.
     *
     * <p>Every instance runs every maintenance task; the conditional update is the election, as the
     * outbox's claim is. Due means the catalogue in use is older than {@code staleBefore} — or there
     * is none — <b>and</b> nobody tried since {@code retryBefore}, so a catalogue that cannot be
     * reached is asked for once per retry interval across the fleet, not once per instance per turn.
     *
     * @return 1 for the instance that won; 0 for the others, and when the row is missing
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ThreatIntelSyncEntity s set s.lastAttemptAt = :now
             where s.id = :id
               and (s.lastSyncedAt is null or s.lastSyncedAt < :staleBefore)
               and (s.lastAttemptAt is null or s.lastAttemptAt < :retryBefore)""")
    int claimScheduled(
            @Param("id") long id,
            @Param("now") Instant now,
            @Param("staleBefore") Instant staleBefore,
            @Param("retryBefore") Instant retryBefore);

    /**
     * Claims an EPSS synchronisation somebody asked for, unless one holds the lease.
     *
     * <p><b>A lease rather than the row lock the KEV sync holds.</b> The KEV catalogue is written in
     * one transaction, so the row's write lock serialises two syncs for free. The EPSS file is written
     * in many short ones — 380,000 rows in one would hold their locks for as long as the engine
     * takes — so exclusivity has to outlive a transaction: whoever claims
     * writes {@code generation} into {@code epss_claim} until {@code leaseUntil}, and every write
     * that follows is conditional on it still being there.
     *
     * @return 1 when claimed; 0 when another synchronisation holds the lease, or the row is missing
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ThreatIntelSyncEntity s
               set s.epssAttemptAt = :now, s.epssLeaseUntil = :leaseUntil, s.epssClaim = :generation
             where s.id = :id
               and (s.epssLeaseUntil is null or s.epssLeaseUntil < :now)""")
    int claimEpss(
            @Param("id") long id,
            @Param("now") Instant now,
            @Param("leaseUntil") Instant leaseUntil,
            @Param("generation") long generation);

    /**
     * Claims the scheduled EPSS synchronisation, when one is due — the file in use older than {@code
     * staleBefore}, or none — nobody tried since {@code retryBefore}, and the lease is free. As
     * {@link #claimScheduled} does for the catalogue, the conditional update is the election.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ThreatIntelSyncEntity s
               set s.epssAttemptAt = :now, s.epssLeaseUntil = :leaseUntil, s.epssClaim = :generation
             where s.id = :id
               and (s.epssSyncedAt is null or s.epssSyncedAt < :staleBefore)
               and (s.epssAttemptAt is null or s.epssAttemptAt < :retryBefore)
               and (s.epssLeaseUntil is null or s.epssLeaseUntil < :now)""")
    int claimEpssScheduled(
            @Param("id") long id,
            @Param("now") Instant now,
            @Param("leaseUntil") Instant leaseUntil,
            @Param("generation") long generation,
            @Param("staleBefore") Instant staleBefore,
            @Param("retryBefore") Instant retryBefore);

    /**
     * Puts a whole, checked file in use: its generation, what its header said, and the lease given
     * back — only if this synchronisation still holds the claim.
     *
     * @param previous the generation in use until now, kept as the previous one (see {@code
     *     EpssFeed}); passed rather than copied from the column in the statement, because MySQL
     *     assigns left to right with the values it has just set and the other engines with the old
     *     ones — only the claim's holder moves the generation, so the value it read is the column's
     * @return 0 when the claim was lost — the lease ran out and another synchronisation took it
     */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
            update ThreatIntelSyncEntity s
               set s.epssGeneration = :generation, s.epssPreviousGeneration = :previous,
                   s.epssStatus = 'SYNCED', s.epssSyncedAt = :now,
                   s.epssModelVersion = :modelVersion, s.epssScoreDate = :scoreDate, s.epssCount = :count,
                   s.epssError = null, s.epssLeaseUntil = null, s.epssClaim = null
             where s.id = :id and s.epssClaim = :generation""")
    int applyEpss(
            @Param("id") long id,
            @Param("generation") long generation,
            @Param("previous") Long previous,
            @Param("now") Instant now,
            @Param("modelVersion") String modelVersion,
            @Param("scoreDate") Instant scoreDate,
            @Param("count") long count);

    /**
     * Records that the file read is the one in use already — same model, same score date — and gives
     * the lease back: synchronised, with nothing rewritten.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ThreatIntelSyncEntity s
               set s.epssStatus = 'SYNCED', s.epssSyncedAt = :now, s.epssError = null,
                   s.epssLeaseUntil = null, s.epssClaim = null
             where s.id = :id and s.epssClaim = :generation""")
    int confirmEpss(@Param("id") long id, @Param("generation") long generation, @Param("now") Instant now);

    /**
     * Records a failed attempt and gives the lease back. The file in use, its generation and its
     * date are left as they are: an outage, or a refused file, is not a file without scores.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ThreatIntelSyncEntity s
               set s.epssStatus = 'FAILED', s.epssError = :error, s.epssLeaseUntil = null, s.epssClaim = null
             where s.id = :id and s.epssClaim = :generation""")
    int failEpss(@Param("id") long id, @Param("generation") long generation, @Param("error") String error);
}
