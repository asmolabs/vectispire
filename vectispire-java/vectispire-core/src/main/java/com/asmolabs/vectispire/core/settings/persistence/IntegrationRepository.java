package com.asmolabs.vectispire.core.settings.persistence;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface IntegrationRepository extends JpaRepository<IntegrationEntity, String> {

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
