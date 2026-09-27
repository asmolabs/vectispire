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
     * <p><b>An update rather than a {@code select … for update}</b>, because SQLite has no row lock
     * to ask for and an update takes the one every engine has. Two synchronisations writing at once
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
}
