package com.asmolabs.vectispire.core.access.persistence;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface LoginAttemptRepository extends JpaRepository<LoginAttemptEntity, UUID> {
    List<LoginAttemptEntity> findByCounterKeyAndOccurredAtAfter(String counterKey, Instant after);

    /** Clears a counter after a success: five mistypes then a correct password is not an attack. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from LoginAttemptEntity a where a.counterKey = :counterKey")
    int deleteByCounterKey(@Param("counterKey") String counterKey);

    /**
     * Takes back the rows an attempt reserved — see {@code AuthService.Reservation}.
     *
     * <p>One statement rather than {@code deleteAllById}, which reads each row before removing it:
     * on SQLite a transaction that reads and then writes is refused outright when another writer
     * committed in between, and concurrent attempts are exactly when this runs.
     */
    @Transactional
    @Modifying
    @Query("delete from LoginAttemptEntity a where a.id in :ids")
    int deleteByIdIn(@Param("ids") java.util.Collection<UUID> ids);

    /**
     * Drops what has left the window.
     *
     * <p>Without it the table grows for every failed login ever made, and the throttle's own
     * query slows down in proportion to how long the deployment has been under attack.
     */
    @Transactional
    @Modifying
    @Query("delete from LoginAttemptEntity a where a.occurredAt < :cutoff")
    int deleteBefore(@Param("cutoff") Instant cutoff);
}
