package com.asmolabs.vectispire.core.gate.persistence;

import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** What the gate has answered, newest first. */
public interface GateVerdicts extends JpaRepository<GateVerdictEntity, java.util.UUID> {

    /**
     * The register, newest first, bounded.
     *
     * <p><b>No visibility clause here, and that is deliberate.</b> Whose estate a row belongs to
     * is decided by {@code Visibility.permits}, once, in one place. A {@code where} rebuilding
     * that rule in JPQL would be a second implementation of the question this codebase has
     * already got wrong twenty-three times — and the first version of this very method got it
     * wrong again, returning everything whenever one of its two id lists was null.
     *
     * <p>The caller therefore filters what comes back. The limit below bounds what is
     * <em>read</em>, so a narrowly restricted reader sees fewer rows than they asked for rather
     * than a page assembled from somebody else's.
     */
    List<GateVerdictEntity> findAllByOrderByDecidedAtDesc(Limit limit);

    /**
     * One page of the register, continuing after a cursor.
     *
     * <p><b>Ordered by instant <em>and</em> id, which the method above is not.</b> A pipeline
     * writes several verdicts in the same millisecond, so an order on the instant alone leaves
     * ties arbitrary — harmless when everything is read at once, and a silent loss when the reader
     * comes back for the next page: rows sharing the boundary instant land on either side
     * depending on what the engine felt like, and some are never returned at all.
     *
     * <p>The id is a UUID and says nothing about time. It does not have to: what a cursor needs is
     * a <em>total</em> order, not a meaningful one.
     *
     * <p>No visibility clause, as everywhere in this file. What that costs here is worth naming:
     * a page can come back empty while the register still has rows the caller may see, so the
     * caller must decide "is there more" from what was <em>read</em> and never from what survived
     * {@code permits}.
     */
    @Query("""
            select v from GateVerdictEntity v
             order by v.decidedAt desc, v.id desc""")
    List<GateVerdictEntity> firstPage(Limit limit);

    /**
     * The page after a cursor.
     *
     * <p><b>A second method rather than a nullable parameter, and {@code TriageEventRepository} says why.</b>
     * A clause written {@code (:decidedAt is null or v.decidedAt < :decidedAt)} runs on SQLite —
     * which the unit suite uses — and fails on PostgreSQL with <i>could not determine data type of
     * parameter</i>: an untyped null in a comparison leaves the driver nothing to infer from. That
     * defect has already shipped once in this codebase, on a route that returned 500 while every
     * test was green.
     */
    @Query("""
            select v from GateVerdictEntity v
             where v.decidedAt < :decidedAt
                or (v.decidedAt = :decidedAt and v.id < :id)
             order by v.decidedAt desc, v.id desc""")
    List<GateVerdictEntity> pageAfter(
            @Param("decidedAt") Instant decidedAt, @Param("id") java.util.UUID id, Limit limit);

    /** One target's verdicts, newest first — what a repository's own page shows. */
    List<GateVerdictEntity> findByRepoIdOrderByDecidedAtDesc(Long repoId, Limit limit);

    List<GateVerdictEntity> findByContainerIdOrderByDecidedAtDesc(Long containerId, Limit limit);

    /** How many refusals and how many passes, for the indicator rather than the list. */
    @Query(
            """
            select v.passed, count(v.id) from GateVerdictEntity v
             where v.decidedAt >= :since
             group by v.passed""")
    List<Object[]> countByOutcomeSince(@Param("since") Instant since);

    /**
     * Drops what is older than the window an operator keeps.
     *
     * <p><b>This table grows with the build rate, not with the estate.</b> A pipeline asks the
     * gate on every push, so a busy fortnight writes more rows than a year of scanning does. The
     * purge is what keeps a register a register rather than a landfill — and the retention window
     * is the operator's, because how far back a proof must reach is an audit question and not a
     * technical one.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from GateVerdictEntity v where v.decidedAt < :cutoff")
    int deleteBefore(@Param("cutoff") Instant cutoff);

    /**
     * The last verdict a target received inside a window — the one that judged the backlog a
     * given scan left behind, if a pipeline asked. Bounded above by the next scan, because a
     * verdict recorded after that one judged a different backlog.
     */
    java.util.Optional<GateVerdictEntity> findFirstByRepoIdAndDecidedAtGreaterThanEqualAndDecidedAtLessThanOrderByDecidedAtDesc(
            Long repoId, Instant from, Instant until);

    java.util.Optional<GateVerdictEntity> findFirstByContainerIdAndDecidedAtGreaterThanEqualAndDecidedAtLessThanOrderByDecidedAtDesc(
            Long containerId, Instant from, Instant until);

    /**
     * The same, with no later scan to close the window. A separate query rather than a far-future
     * bound: {@code Instant.MAX} does not fit a MySQL or PostgreSQL timestamp.
     */
    java.util.Optional<GateVerdictEntity> findFirstByRepoIdAndDecidedAtGreaterThanEqualOrderByDecidedAtDesc(
            Long repoId, Instant from);

    java.util.Optional<GateVerdictEntity> findFirstByContainerIdAndDecidedAtGreaterThanEqualOrderByDecidedAtDesc(
            Long containerId, Instant from);
}
