package com.asmolabs.vectispire.core.access.persistence;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** Sign-ins waiting for their verification code. Looked up by the hash of the challenge token. */
public interface MfaChallengeRepository extends JpaRepository<MfaChallengeEntity, String> {

    /**
     * Counts one wrong code, and says how many there have now been.
     *
     * <p><b>An update rather than read-modify-write.</b> Two wrong codes arriving at once against
     * the same challenge would each read {@code 2}, each write {@code 3}, and leave a challenge
     * that has absorbed four guesses while believing it has seen three. The whole value of the
     * counter is that it is exact, so the database increments it.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update MfaChallengeEntity c set c.attempts = c.attempts + 1 where c.tokenHash = :tokenHash")
    int countAttempt(@Param("tokenHash") String tokenHash);

    /**
     * Drops what nobody came back for.
     *
     * <p>An abandoned sign-in — the tab closed between the password and the code — leaves a row
     * that no later presentation will remove, because there will not be one.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from MfaChallengeEntity c where c.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);

    /**
     * Destroys one challenge.
     *
     * <p>One statement rather than {@code deleteById}, which reads the row before removing it:
     * codes presented together all end here, and on SQLite a transaction that reads and then writes
     * is refused outright when another writer committed in between.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from MfaChallengeEntity c where c.tokenHash = :tokenHash")
    int discard(@Param("tokenHash") String tokenHash);

    /** How many are live, for the cap that stops a flood of abandoned sign-ins growing the table. */
    long countByExpiresAtAfter(Instant now);
}
