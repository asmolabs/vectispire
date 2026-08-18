package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.IssueEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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
}
