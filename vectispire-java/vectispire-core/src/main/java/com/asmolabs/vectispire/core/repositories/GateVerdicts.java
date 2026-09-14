package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.GateVerdictEntity;
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
}
