package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.IssueEntity;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface Issues extends JpaRepository<IssueEntity, Long> {
    Optional<IssueEntity> findByFingerprint(String fingerprint);

    List<IssueEntity> findByFingerprintIn(java.util.Collection<String> fingerprints);

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
}
