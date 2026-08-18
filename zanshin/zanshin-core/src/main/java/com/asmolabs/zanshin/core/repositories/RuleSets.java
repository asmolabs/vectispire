package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.SemgrepRuleSetEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The uploaded Semgrep rule sets.
 *
 * <p>{@code isActive} is {@code Boolean}, and {@code null} rather than {@code false} is
 * what "not active" means: the unique index over that column is what enforces "at most one
 * active", and an index only counts NULLs as distinct.
 */
public interface RuleSets extends JpaRepository<SemgrepRuleSetEntity, Long> {
    Optional<SemgrepRuleSetEntity> findByIsActiveTrue();

    Optional<SemgrepRuleSetEntity> findByContentHash(String contentHash);

    /**
     * The listing, without the files.
     *
     * <p>The files are megabytes of YAML. A listing that carried them would be a listing
     * nobody opens twice, and the projection is what stops a lazy `findAll` from becoming
     * that by accident.
     */
    @Query("""
            select new com.asmolabs.zanshin.core.repositories.RuleSetSummary(
                    r.id, r.name, r.contentHash, r.ruleCount, r.fileCount, r.sizeBytes,
                    r.isActive, r.uploadedBy, r.uploadedAt, r.activationNote)
              from SemgrepRuleSetEntity r
             order by r.uploadedAt desc, r.id desc""")
    List<RuleSetSummary> summaries();

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update SemgrepRuleSetEntity r set r.isActive = null where r.isActive = true")
    int deactivateAll();

    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update SemgrepRuleSetEntity r set r.isActive = true, r.activationNote = :note where r.id = :id")
    int activate(@Param("id") Long id, @Param("note") String note);
}
