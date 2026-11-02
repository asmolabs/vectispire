package com.asmolabs.vectispire.core.access.persistence;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface SignInClientRepository extends JpaRepository<SignInClientEntity, String> {

    boolean existsByClientKeyAndLastSignedInAtAfter(String clientKey, Instant after);

    /**
     * Refreshes a known client in one statement — the common case, every sign-in from a usual place.
     *
     * @return 0 when the client is new to the account, and the caller inserts it
     */
    @Transactional
    @Modifying
    @Query("update SignInClientEntity c set c.lastSignedInAt = :at where c.clientKey = :clientKey")
    int touch(@Param("clientKey") String clientKey, @Param("at") Instant at);

    /** Forgets the clients that have not signed in for the retention — see {@code SessionCleanupService}. */
    @Transactional
    @Modifying
    @Query("delete from SignInClientEntity c where c.lastSignedInAt < :cutoff")
    int deleteBefore(@Param("cutoff") Instant cutoff);
}
