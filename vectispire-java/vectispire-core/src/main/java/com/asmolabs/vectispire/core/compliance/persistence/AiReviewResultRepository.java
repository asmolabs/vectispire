package com.asmolabs.vectispire.core.compliance.persistence;

import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface AiReviewResultRepository extends JpaRepository<AiReviewResultEntity, Long> {

    /**
     * The most recent report about one repository, whichever scan it was built from.
     *
     * <p>Keyed through the scan rather than stored against the repository: a report is a
     * statement about a moment, and the scan is what dates it and names the version. Asking for
     * "the latest" is then a question about scans, which is the only ordering that means
     * anything here.
     */
    @Query("""
            select r from AiReviewResultEntity r, ScanEntity s
             where r.scanId = s.id and s.repoId = :repoId
             order by r.createdAt desc, r.id desc""")
    List<AiReviewResultEntity> latestForRepository(@Param("repoId") long repoId, Limit limit);

    @Transactional
    void deleteByScanIdIn(java.util.Collection<Long> scanIds);

    /**
     * Settles as failed the reviews still running past their deadline — requests whose process
     * stopped between asking the model and writing its answer.
     *
     * <p>Conditional on the status in the {@code where}, so a review settled by its own request at
     * the same moment keeps what the model said: the sweep only ever turns a {@code running} row into
     * a failed one, never a finished one.
     */
    @Transactional
    @Modifying
    @Query("""
            update AiReviewResultEntity r set r.status = :failed, r.error = :error, r.deadlineAt = null
             where r.status = :running and r.deadlineAt < :now""")
    int settleAbandoned(
            @Param("running") String running,
            @Param("failed") String failed,
            @Param("error") String error,
            @Param("now") java.time.Instant now);
}
