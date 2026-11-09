package com.asmolabs.vectispire.core.settings.persistence;

import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface IntegrationRepository extends JpaRepository<IntegrationEntity, String> {

    /**
     * {@code select … for update} on one integration's row, held until the caller's transaction ends: the
     * governor's switch takes it before it asks whether the integration is in use, so a configuration
     * that starts using it waits for the switch, or the switch for the configuration — never both at once.
     * Empty for a key without a row, which reads disabled and has nothing to guard.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select i from IntegrationEntity i where i.key = :key")
    Optional<IntegrationEntity> lockForSwitch(@Param("key") String key);

    /**
     * {@code select … for share}: what a configuration that starts using an integration takes, so that two
     * saves do not wait for each other and the governor's switch waits for both.
     */
    @Lock(LockModeType.PESSIMISTIC_READ)
    @Query("select i from IntegrationEntity i where i.key = :key")
    Optional<IntegrationEntity> lockForUse(@Param("key") String key);

    /**
     * Switches a row that is not already in the wanted state, and says whether it did.
     *
     * <p>Conditional, so that two governors switching the same integration the same way at once change it
     * once: a read-then-write let both read "enabled", both write "disabled", and both record a change.
     *
     * @return 1 when the row changed; 0 when it was already so, or when there is no row
     */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update IntegrationEntity i set i.enabled = :enabled, i.updatedAt = :at, i.updatedBy = :by "
            + "where i.key = :key and i.enabled <> :enabled")
    int switchTo(@Param("key") String key, @Param("enabled") boolean enabled, @Param("at") Instant at,
            @Param("by") String by);
}
