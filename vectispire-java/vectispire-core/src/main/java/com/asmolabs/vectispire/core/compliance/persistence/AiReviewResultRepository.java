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
     * <p>A report is a statement about a moment, and its scan is what dates it and names the version,
     * so the row is keyed by the scan. The repository beside it is that scan's, copied when the
     * review is requested (V62): the question "which repository" is answered without joining the
     * scans' table, and cannot answer otherwise than the join did, since a scan never changes target.
     */
    @Query("""
            select r from AiReviewResultEntity r
             where r.repoId = :repoId
             order by r.createdAt desc, r.id desc""")
    List<AiReviewResultEntity> latestForRepository(@Param("repoId") long repoId, Limit limit);

    /**
     * Whether some review is under way and still awaited: in this status, its deadline after {@code now}.
     * A running row past its deadline is one a stopped process left behind, and waiting for it would wait
     * for nothing.
     */
    boolean existsByStatusAndDeadlineAtAfter(String status, java.time.Instant now);

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
