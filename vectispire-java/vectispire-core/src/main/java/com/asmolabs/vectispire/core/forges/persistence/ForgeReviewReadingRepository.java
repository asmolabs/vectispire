package com.asmolabs.vectispire.core.forges.persistence;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The change-review readings (decision 0037, lot G3), one per repository target and branch. */
public interface ForgeReviewReadingRepository extends JpaRepository<ForgeReviewReadingEntity, Long> {

    Optional<ForgeReviewReadingEntity> findByRepositoryIdAndWantedBranch(Long repositoryId, String wantedBranch);

    /** The readings of these repositories for one branch; called a thousand ids at a time, under the bind limit. */
    List<ForgeReviewReadingEntity> findByWantedBranchAndRepositoryIdIn(String wantedBranch, Collection<Long> repositoryIds);

    /** Every repository read, for the turn's sweep of the readings no line asks for any more. */
    @Query("select distinct r.repositoryId from ForgeReviewReadingEntity r")
    List<Long> repositoriesRead();

    /**
     * Claims a reading for this instance: only when no other holds it and it is due — never read, read before
     * {@code staleBefore}, or over a window narrower than the one now asked. One row or none: the instance that
     * changed it reads the forge, the others go on.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update ForgeReviewReadingEntity r set r.claimedUntil = :until
             where r.id = :id and (r.claimedUntil is null or r.claimedUntil < :now)
               and (r.readAt is null or r.readAt < :staleBefore or r.windowDays < :windowDays)""")
    int claim(@Param("id") long id, @Param("now") Instant now, @Param("until") Instant until,
            @Param("staleBefore") Instant staleBefore, @Param("windowDays") int windowDays);

    /** Lets go of a claim whose reading did not happen: the previous reading stands. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ForgeReviewReadingEntity r set r.claimedUntil = null where r.id = :id")
    int release(@Param("id") long id);

    /** A deleted target's readings, in the deleting transaction ({@code TargetDeleted}). */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ForgeReviewReadingEntity r where r.repositoryId = :repositoryId")
    int deleteByRepository(@Param("repositoryId") long repositoryId);

    /** Readings of targets no line asks for any more, or that are gone; a batch of ids at a time. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ForgeReviewReadingEntity r where r.repositoryId in :repositoryIds")
    int deleteByRepositories(@Param("repositoryIds") Collection<Long> repositoryIds);

    /** A deleted connection's readings: what it read is no longer anybody's to vouch for. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ForgeReviewReadingEntity r where r.connectionId = :connectionId")
    int deleteByConnection(@Param("connectionId") UUID connectionId);
}
