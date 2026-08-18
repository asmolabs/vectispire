package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.OutboxMessageEntity;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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

    @Modifying(clearAutomatically = true)
    @Query("delete from OutboxMessageEntity m where m.status = :status and m.sentAt is not null and m.sentAt < :cutoff")
    int deleteSentBefore(@Param("status") String status, @Param("cutoff") Instant cutoff);

    @Query("select m.status, count(m.id) from OutboxMessageEntity m group by m.status")
    List<Object[]> countByStatus();
}
