package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.TriageEventEntity;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface TriageEvents extends JpaRepository<TriageEventEntity, Long> {

    List<TriageEventEntity> findByIssueIdOrderByOccurredAtAscIdAsc(long issueId);

    /**
     * The decisions taken on a set of issues, oldest first.
     *
     * <p><b>One query for a page of issues, not one per issue.</b> The history screen shows a
     * scan's whole finding list with each issue's decisions under it; asking per row turns one
     * page into hundreds of round trips, which is invisible on a demo database and is the
     * difference between a screen and a timeout on a real backlog.
     */
    @Query("""
            select e from TriageEventEntity e
             where e.issueId in :issueIds
             order by e.occurredAt asc, e.id asc""")
    List<TriageEventEntity> findForIssues(@Param("issueIds") Collection<Long> issueIds);

    /**
     * How many decisions were ever taken on one repository's issues.
     *
     * <p><b>A count, and no date window.</b> The first version took a nullable {@code from}/{@code
     * to} pair written as {@code (:from is null or e.occurredAt >= :from)}. That runs on SQLite —
     * which is what the HTTP suite uses — and fails on PostgreSQL with <i>could not determine data
     * type of parameter $2</i>: an untyped null in a comparison leaves the driver nothing to infer
     * from. The whole history page returned 500 while every test was green, which is the exact
     * portability defect the four-engine campaign exists to catch and that a single engine cannot.
     *
     * <p>The window went with it rather than being cast into shape: nothing asked for it yet, and
     * a parameter no caller passes is one nobody exercises. It comes back the day an export by
     * period does, with an engine-agnostic shape and a test on more than one engine.
     */
    @Query("""
            select count(e.id) from TriageEventEntity e, IssueEntity i
             where e.issueId = i.id and i.repoId = :repoId""")
    long countForRepository(@Param("repoId") long repoId);
}
