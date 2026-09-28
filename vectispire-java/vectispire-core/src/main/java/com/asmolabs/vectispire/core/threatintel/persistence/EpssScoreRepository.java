package com.asmolabs.vectispire.core.threatintel.persistence;

import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * The stored EPSS scores, one generation of FIRST's file at a time.
 *
 * <p>Every read names its generation — the one the sync row says is in use — so a generation being
 * written, or one refused half-way, is never seen.
 */
@Repository
public interface EpssScoreRepository extends JpaRepository<EpssScoreEntity, EpssScoreEntity.Key>, EpssScoreBulkWrites {

    /**
     * The scores of these identifiers in one generation.
     *
     * @param ids upper-case, as stored — compared as given, so the key's index is used; a {@code
     *     lower(…)} on the column, as the KEV lookup has, would read the whole generation
     */
    @Query("""
            select new com.asmolabs.vectispire.core.threatintel.persistence.KnownEpssScore(
                   e.cveId, e.score, e.percentile)
              from EpssScoreEntity e
             where e.generation = :generation and e.cveId in :ids""")
    List<KnownEpssScore> scoresOf(@Param("generation") long generation, @Param("ids") Collection<String> ids);

    long countByGeneration(long generation);

    /**
     * Every generation stored but these: those a refused or interrupted synchronisation left, and the
     * one replaced two files ago.
     *
     * @param keep never empty — an empty {@code in} list is a syntax error on some engines
     */
    @Query("select distinct e.generation from EpssScoreEntity e where e.generation not in :keep")
    List<Long> generationsOtherThan(@Param("keep") Collection<Long> keep);

    /**
     * The identifiers of one generation, in key order, a page at a time — used for one row, the
     * boundary of the next batch to delete.
     */
    @Query("select e.cveId from EpssScoreEntity e where e.generation = :generation order by e.cveId")
    List<String> cveIdsOf(@Param("generation") long generation, Pageable page);

    /**
     * Deletes one generation's rows up to a boundary, in key order.
     *
     * <p><b>A range, not {@code in (select … limit)}</b>: MySQL refuses a {@code limit} inside an
     * {@code in} subquery, and PostgreSQL has no {@code delete … limit}. The boundary is read first,
     * then everything at or below it goes in one statement bounded by the key.
     */
    @Transactional
    @Modifying
    @Query("delete from EpssScoreEntity e where e.generation = :generation and e.cveId <= :upTo")
    int deleteUpTo(@Param("generation") long generation, @Param("upTo") String upTo);

    /** Deletes what is left of one generation — at most one batch, when called after {@link #deleteUpTo}. */
    @Transactional
    @Modifying
    @Query("delete from EpssScoreEntity e where e.generation = :generation")
    int deleteGeneration(@Param("generation") long generation);
}
