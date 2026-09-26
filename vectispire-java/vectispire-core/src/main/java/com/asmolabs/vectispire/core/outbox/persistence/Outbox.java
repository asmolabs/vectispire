package com.asmolabs.vectispire.core.outbox.persistence;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The notification queue.
 *
 * <p>Written inside the transaction that commits a scan's results, drained later by the
 * relay. The updates below are targeted rather than entity saves: the relay settles a
 * message from outside any persistence context that loaded it, and a dirty check there would
 * rewrite a payload it never meant to touch.
 */
public interface Outbox extends JpaRepository<OutboxMessageEntity, UUID> {

    /**
     * The messages due now, oldest first.
     *
     * <p>{@code nextAttemptAt is null} is a first attempt, not a missing value: a message
     * that has never been tried is due immediately, and reading null as "not yet" would
     * leave the whole queue permanently just about to go out.
     */
    @Query("""
            select m from OutboxMessageEntity m
             where m.status = :status and (m.nextAttemptAt is null or m.nextAttemptAt <= :at)
             order by m.createdAt asc, m.id asc""")
    List<OutboxMessageEntity> findDue(@Param("status") String status, @Param("at") Instant at, Limit limit);

    /**
     * Takes one due message for this instance, or reports that another one already has.
     *
     * <p>The condition is the whole mechanism: it repeats {@link #findDue}'s, so of two instances
     * that read the same due row, the second update finds its next attempt already pushed ahead
     * and changes nothing. Committed on its own, before the delivery, so the others see it.
     *
     * @return 1 when this caller holds the message until {@code until}, 0 when someone else does
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update OutboxMessageEntity m set m.nextAttemptAt = :until
             where m.id = :id and m.status = :status and (m.nextAttemptAt is null or m.nextAttemptAt <= :at)""")
    int claim(
            @Param("id") UUID id,
            @Param("status") String status,
            @Param("at") Instant at,
            @Param("until") Instant until);

    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update OutboxMessageEntity m
               set m.attempts = :attempts, m.lastError = :lastError,
                   m.status = :status, m.nextAttemptAt = :nextAttemptAt
             where m.id = :id""")
    int recordAttempt(
            @Param("id") UUID id,
            @Param("attempts") int attempts,
            @Param("lastError") String lastError,
            @Param("status") String status,
            @Param("nextAttemptAt") Instant nextAttemptAt);

    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update OutboxMessageEntity m
               set m.attempts = :attempts, m.status = :status, m.sentAt = :sentAt,
                   m.nextAttemptAt = null, m.lastError = null
             where m.id = :id""")
    int markSent(
            @Param("id") UUID id,
            @Param("attempts") int attempts,
            @Param("status") String status,
            @Param("sentAt") Instant sentAt);

    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from OutboxMessageEntity m where m.status = :status and m.sentAt is not null and m.sentAt < :cutoff")
    int deleteSentBefore(@Param("status") String status, @Param("cutoff") Instant cutoff);

    @Query("select m.status, count(m.id) from OutboxMessageEntity m group by m.status")
    List<Object[]> countByStatus();
}
