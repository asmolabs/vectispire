package com.asmolabs.vectispire.core.compliance.persistence;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The weekly OWASP record.
 *
 * <p><b>No visibility clause in what is here</b>, which writes and purges: the capture is of the
 * whole estate, like the compliance history. A read for a reader narrows by target, which is what the
 * per-target rows exist for: {@link OwaspWeeklyCoverageQueries}.
 */
public interface OwaspWeeklyCoverageRepository
        extends JpaRepository<OwaspWeeklyCoverageEntity, Long>, OwaspWeeklyCoverageQueries {

    /** When this week was last written, by any instance — the capture's gate. */
    @Query("select max(c.capturedAt) from OwaspWeeklyCoverageEntity c where c.weekStart = :week")
    Optional<Instant> newestCaptureOf(@Param("week") Instant week);

    /** The week's rows, before they are written again. Never another week's: a closed week keeps its end. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from OwaspWeeklyCoverageEntity c where c.weekStart = :week")
    int deleteWeek(@Param("week") Instant week);

    /**
     * A target's rows, every week — in the deleting transaction. Flushed first and nothing cleared:
     * the other listeners of the purge share this persistence context.
     */
    @Transactional
    @Modifying(flushAutomatically = true)
    @Query("delete from OwaspWeeklyCoverageEntity c where c.targetKind = :kind and c.targetId = :id")
    int deleteByTarget(@Param("kind") String kind, @Param("id") long id);

    /** Every target the record names, once each. */
    @Query("select distinct new com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyTarget(c.targetKind, c.targetId)"
            + " from OwaspWeeklyCoverageEntity c")
    List<OwaspWeeklyTarget> targets();

    List<OwaspWeeklyCoverageEntity> findByWeekStart(Instant weekStart);
}
