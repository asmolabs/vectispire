package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.SemgrepRuleSetEntity;
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

    /**
     * A set by the hash of its content — <b>first match, and the hash is not unique</b>.
     *
     * <p>Importing the same catalogue selection twice stores two rows: they carry the same files
     * and therefore the same hash, and differ only by who imported them and when. That metadata
     * is worth keeping, so the duplicate is not prevented — but the lookup has to survive it.
     * Declared as a plain {@code Optional} it did not: Spring Data raised "Query did not return a
     * unique result: 2 results were returned", which reached an operator as a failed SAST step on
     * every scan, from the moment a set was re-imported.
     *
     * <p>Which row answers cannot change what is scanned: the hash <em>is</em> the content, so
     * two rows sharing one are byte-identical by construction. Ordering by id only makes the
     * choice deterministic rather than incidental.
     */
    Optional<SemgrepRuleSetEntity> findFirstByContentHashOrderByIdAsc(String contentHash);

    /**
     * The listing, without the files.
     *
     * <p>The files are megabytes of YAML. A listing that carried them would be a listing
     * nobody opens twice, and the projection is what stops a lazy `findAll` from becoming
     * that by accident.
     */
    @Query("""
            select new com.asmolabs.vectispire.core.repositories.RuleSetSummary(
                    r.id, r.name, r.contentHash, r.ruleCount, r.fileCount, cast(r.sizeBytes as string),
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
