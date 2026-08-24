package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.LoginAttemptEntity;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface LoginAttempts extends JpaRepository<LoginAttemptEntity, UUID> {
    List<LoginAttemptEntity> findByCounterKeyAndOccurredAtAfter(String counterKey, Instant after);

    /** Clears a counter after a success: five mistypes then a correct password is not an attack. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from LoginAttemptEntity a where a.counterKey = :counterKey")
    int deleteByCounterKey(@Param("counterKey") String counterKey);

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
