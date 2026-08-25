package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.IssueEntity;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface Issues
        extends JpaRepository<IssueEntity, Long>, JpaSpecificationExecutor<IssueEntity>, IssueAggregates {
    Optional<IssueEntity> findByFingerprint(String fingerprint);

    List<IssueEntity> findByFingerprintIn(java.util.Collection<String> fingerprints);

    List<IssueEntity> findByIdentifier(String identifier);

    /**
     * The open issues of one target, restricted to the types a scan actually looked at.
     *
     * <p>The type filter is the whole safety of the resolution pass: without it a scan that
     * only looked for secrets would resolve the target's vulnerabilities as well.
     */
    @Query("""
            select i from IssueEntity i
             where i.state = :state and i.type in :types
               and ((:repoId is not null and i.repoId = :repoId)
                    or (:containerId is not null and i.containerId = :containerId))""")
    List<IssueEntity> findOpenByTarget(
            @Param("state") String state,
            @Param("types") java.util.Collection<String> types,
            @Param("repoId") Long repoId,
            @Param("containerId") Long containerId);

    /**
     * Every open issue counted once, grouped by target and by the three axes the compliance
     * summary reports on.
     *
     * <p><b>One query for a page of targets, not nine per target.</b> The summary asked for four
     * severities, the KEV flag and three finding types, per target, inside its loop — nine round
     * trips per row, so a hundred-target estate produced nine hundred for one page. That is the
     * shape {@code TriageEvents.findForIssues} was written to avoid, and it is invisible on the
     * SQLite suite for the same reason: a demo database answers all nine before anyone notices.
     *
     * <p><b>Visibility is not applied here, deliberately, and that is safe because it is purely
     * target-scoped.</b> {@code IssueFilters} restricts by {@code repoId}/{@code containerId} and
     * nothing else, so grouping by target and reading only the groups whose target the caller can
     * already see gives exactly the same numbers. The caller is responsible for that last step —
     * which it does by iterating the visibility-filtered target list rather than this result.
     *
     * @return rows of {@code [repoId, containerId, severity, type, isKev, count]}
     */
    @Query("""
            select i.repoId, i.containerId, i.severity, i.type, i.isKev, count(i.id)
              from IssueEntity i
             where i.state = :state
             group by i.repoId, i.containerId, i.severity, i.type, i.isKev""")
    List<Object[]> countOpenGroupedByTarget(@Param("state") String state);

    /**
     * Open issues of one type, counted by the identifier that produced them.
     *
     * <p>Read from the issue alone: it carries its own type and identifier, and that
     * identifier <em>is</em> the analyser's rule id. Joining the findings to reach it would
     * add a join for a column already here, and would count an issue once per scan that saw
     * it.
     */

    @Query("""
            select i.identifier, count(i.id) from IssueEntity i
             where i.state = :state and i.type = :type and i.identifier is not null
             group by i.identifier""")
    List<Object[]> countOpenByIdentifier(@Param("state") String state, @Param("type") String type);

    /**
     * Open, not dismissed, and with no ticket yet.
     *
     * <p>{@code not_affected} and {@code fixed} are excluded: those are the two judgments that
     * say "nothing to plan". Everything else — including {@code under_review}, which is the
     * default — stays a candidate, because an issue nobody has looked at yet is exactly the one
     * that needs to exist somewhere other than a dashboard.
     *
     * <p><b>Most severe first</b>, not oldest first: the per-pass ceiling has to serve what
     * matters most. A mature backlog ordered by identifier would spend its twenty tickets on
     * harmless findings inserted a year ago, and yesterday's critical would wait days for its
     * turn.
     */
    @Query("""
            select i from IssueEntity i
             where i.state = :state and i.ticketRef is null and i.triageStatus not in :excluded
             order by case i.severity
                        when 'critical' then 0 when 'high' then 1 when 'medium' then 2
                        when 'low' then 3 when 'negligible' then 4 else 5 end asc,
                      i.id asc""")
    List<IssueEntity> findActionableWithoutTicket(
            @Param("state") String state, @Param("excluded") Collection<String> excluded, Limit limit);

    @Query("select i from IssueEntity i where i.ticketRef = :ref or i.ticketRef = concat('#', :ref)")
    Optional<IssueEntity> findByTicketRefOrIid(@Param("ref") String ref);

    @Query("select i from IssueEntity i where i.state = 'resolved' and i.ticketRef is not null and not i.ticketRef like 'CLOSED:%'")
    List<IssueEntity> findResolvedWithOpenTicket(Limit limit);

    /**
     * Records the ticket a sweep opened.
     *
     * <p>Set once and never cleared: it is what stops a ticket rising from the dead on every
     * rescan, and it is the sweep's deduplication key.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update IssueEntity i set i.ticketRef = :reference, i.ticketUrl = :url where i.id = :id")
    int attachTicket(@Param("id") Long id, @Param("reference") String reference, @Param("url") String url);

    /**
     * The issues whose review date has passed.
     *
     * <p>Selected on the date alone, and the caller re-checks the status: the rule that decides
     * what counts as expired lives in the domain, and duplicating it here would be two answers
     * to one question, disagreeing the day either changes.
     */
    @Query("select i from IssueEntity i where i.triageExpiresAt is not null and i.triageExpiresAt <= :asOf")
    List<IssueEntity> findWithExpiredTriage(@Param("asOf") Instant asOf);

    /**
     * One repository's issues in a given state, in full.
     *
     * <p>Ordered so a report built from them reads the same twice: severity has no natural SQL
     * order, so the identifier decides, and a digest that reshuffles on every run would make two
     * reports differ for no reason anybody could point at.
     */
    @Query("""
            select i from IssueEntity i
             where i.repoId = :repoId and i.state = :state
             order by i.type asc, i.identifier asc, i.id asc""")
    List<IssueEntity> findByRepositoryAndState(@Param("repoId") Long repoId, @Param("state") String state);

    /** One repository's open issues, for a page that shows one target rather than all of them. */
    @Query("""
            select count(i.id) from IssueEntity i
             where i.state = :state and i.repoId = :repoId""")
    long countByStateAndRepository(@Param("state") String state, @Param("repoId") Long repoId);

    /** Open issues per repository, for the target list's badge. */
    @Query("""
            select i.repoId, count(i.id) from IssueEntity i
             where i.state = :state and i.repoId is not null
             group by i.repoId""")
    List<Object[]> countOpenByRepository(@Param("state") String state);

    @Query("""
            select i.containerId, count(i.id) from IssueEntity i
             where i.state = :state and i.containerId is not null
             group by i.containerId""")
    List<Object[]> countOpenByContainer(@Param("state") String state);

    /** Every issue in one state, for the gate and the security overview. */
    List<IssueEntity> findByState(String state);

    /**
     * The heaviest rules, files or targets of one issue type.
     *
     * <p>Three queries rather than one parameterized by a column name: a column name that
     * arrives as a string is a column name that can arrive from a request, and "the grouping
     * axis is injectable" is how a filter becomes an injection point.
     */
    @Query("""
            select i.identifier, count(i.id) as total from IssueEntity i
             where i.state = :state and i.type = :type
             group by i.identifier
             order by total desc""")
    List<Object[]> countOpenByRule(@Param("state") String state, @Param("type") String type, Limit limit);

    @Query("""
            select i.filePath, count(i.id) as total from IssueEntity i
             where i.state = :state and i.type = :type
             group by i.filePath
             order by total desc""")
    List<Object[]> countOpenByFile(@Param("state") String state, @Param("type") String type, Limit limit);

    @Query("""
            select i.repoId, count(i.id) as total from IssueEntity i
             where i.state = :state and i.type = :type and i.repoId is not null
             group by i.repoId
             order by total desc""")
    List<Object[]> countOpenByTargetRepository(@Param("state") String state, @Param("type") String type, Limit limit);

    /** The backlog by severity, for the dashboard's headline figures. */
    @Query("""
            select i.severity, count(i.id) from IssueEntity i
             where i.state = :state
             group by i.severity""")
    List<Object[]> countOpenBySeverity(@Param("state") String state);

    long countByStateAndType(String state, String type);

    /**
     * How many distinct rules — or files — the backlog of one type touches.
     *
     * <p>Counted rather than taken from the length of the top-N list, which is what the NestJS
     * screen did: it always answered "8" once there were eight or more, so the figure meant
     * "the list below is full" and read as "the debt comes from eight rules".
     */
    @Query("""
            select count(distinct i.identifier) from IssueEntity i
             where i.state = :state and i.type = :type and i.identifier is not null""")
    long countDistinctRules(@Param("state") String state, @Param("type") String type);

    @Query("""
            select count(distinct i.filePath) from IssueEntity i
              where i.state = :state and i.type = :type and i.filePath is not null""")
    long countDistinctFiles(@Param("state") String state, @Param("type") String type);

    @Query("select i.id from IssueEntity i where i.containerId = :containerId")
    List<Long> findIdsByContainerId(@Param("containerId") Long containerId);

    @Query("select i.id from IssueEntity i where i.repoId = :repoId")
    List<Long> findIdsByRepoId(@Param("repoId") Long repoId);

    @Query("""
            select i.id from IssueEntity i
             where (i.containerId is not null and i.containerId not in (select c.id from ContainerEntity c))
                or (i.repoId is not null and i.repoId not in (select r.id from RepositoryEntity r))""")
    List<Long> findOrphanedIds();

    @Modifying
    @Query("delete from IssueEntity i where i.id in :ids")
    void deleteByIdIn(@Param("ids") Collection<Long> ids);
}
