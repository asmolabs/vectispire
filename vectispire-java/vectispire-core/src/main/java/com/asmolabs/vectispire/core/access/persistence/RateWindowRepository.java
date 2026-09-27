package com.asmolabs.vectispire.core.access.persistence;

import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The shared request counters.
 *
 * <p>Each write is one statement in its own transaction, and none is a {@code save}: an increment
 * read in Java and written back would lose every hit another instance made in between, and a first
 * hit that merged would overwrite a count somebody had just started.
 */
public interface RateWindowRepository extends JpaRepository<RateWindowEntity, String> {

    /** One more hit in a window that already has a row; zero rows when it has none yet. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update RateWindowEntity w set w.hits = w.hits + 1 where w.windowKey = :key")
    int increment(@Param("key") String key);

    /**
     * The window's first hit, as a bare insert: two instances that both found no row both try it,
     * and the primary key refuses the second, which then increments.
     *
     * <p>Native, for the reason {@code LeaderLeaseRepository.insertNew} gives: {@code save} would
     * merge, and the last writer would win.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query(
            value = "insert into t_rate_window (window_key, hits, expires_at) values (:key, 1, :expiresAt)",
            nativeQuery = true)
    int insertFirst(@Param("key") String key, @Param("expiresAt") Instant expiresAt);

    @Query("select w.hits from RateWindowEntity w where w.windowKey = :key")
    Optional<Integer> hitsOf(@Param("key") String key);

    /** The windows that have closed. Nothing reads a closed window again. */
    @Transactional
    @Modifying
    @Query("delete from RateWindowEntity w where w.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);

    /** Every window of one limit. For the tests, through {@code RateWindows.forget}. */
    @Transactional
    @Modifying
    @Query("delete from RateWindowEntity w where w.windowKey like :prefix")
    int deleteByKeyPrefix(@Param("prefix") String prefix);
}
