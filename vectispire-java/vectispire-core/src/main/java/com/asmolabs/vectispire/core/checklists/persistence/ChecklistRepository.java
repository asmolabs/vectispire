package com.asmolabs.vectispire.core.checklists.persistence;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The project checklists, each revision a row.
 *
 * <p><b>Every change to a revision is a conditional statement on the edition its writer read</b>,
 * whose row count names the winner — the template versions' rule ({@code
 * ChecklistTemplateVersionRepository}). An answer racing a submission, two sign-offs of one revision,
 * a return racing a sign-off: in each, one statement matches and the other matches nothing, and its
 * caller refuses rather than acting on a state it did not see.
 */
public interface ChecklistRepository extends JpaRepository<ChecklistEntity, Long> {

    List<ChecklistEntity> findByProjectIdOrderByRevisionDesc(Long projectId);

    Optional<ChecklistEntity> findByProjectIdAndRevision(Long projectId, Integer revision);

    Optional<ChecklistEntity> findFirstByProjectIdOrderByRevisionDesc(Long projectId);

    /** A write to a draft's lines — an answer, a proof — counted, if it is still the draft read. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ChecklistEntity c set c.edition = c.edition + 1"
            + " where c.id = :id and c.edition = :edition and c.status = :draft")
    int touchDraft(@Param("id") long id, @Param("edition") int edition, @Param("draft") String draft);

    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ChecklistEntity c set c.status = :submitted, c.edition = c.edition + 1, c.submittedAt = :at,"
            + " c.submittedBy = :by, c.submittedById = :byId"
            + " where c.id = :id and c.edition = :edition and c.status = :draft")
    int submit(
            @Param("id") long id,
            @Param("edition") int edition,
            @Param("draft") String draft,
            @Param("submitted") String submitted,
            @Param("at") Instant at,
            @Param("by") String by,
            @Param("byId") long byId);

    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ChecklistEntity c set c.status = :draft, c.edition = c.edition + 1, c.returnedAt = :at,"
            + " c.returnedBy = :by, c.returnReason = :reason"
            + " where c.id = :id and c.edition = :edition and c.status = :submitted")
    int returnToDraft(
            @Param("id") long id,
            @Param("edition") int edition,
            @Param("submitted") String submitted,
            @Param("draft") String draft,
            @Param("at") Instant at,
            @Param("by") String by,
            @Param("reason") String reason);

    /** Signs a submitted revision off, and frees the project's open slot. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ChecklistEntity c set c.status = :signedOff, c.edition = c.edition + 1, c.openSlot = null,"
            + " c.signedOffAt = :at, c.signedOffBy = :by, c.signedOffById = :byId, c.signOffFourEyes = :fourEyes"
            + " where c.id = :id and c.edition = :edition and c.status = :submitted")
    int signOff(
            @Param("id") long id,
            @Param("edition") int edition,
            @Param("submitted") String submitted,
            @Param("signedOff") String signedOff,
            @Param("at") Instant at,
            @Param("by") String by,
            @Param("byId") long byId,
            @Param("fourEyes") boolean fourEyes);

    /** An open revision set aside by the next one, freeing the project's open slot for it. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ChecklistEntity c set c.status = :superseded, c.edition = c.edition + 1, c.openSlot = null,"
            + " c.supersededAt = :at, c.supersededBy = :by"
            + " where c.id = :id and c.edition = :edition and c.status in :open")
    int supersede(
            @Param("id") long id,
            @Param("edition") int edition,
            @Param("open") List<String> open,
            @Param("superseded") String superseded,
            @Param("at") Instant at,
            @Param("by") String by);

    /** A project's checklists, for its deletion (decision 0032, question 10). */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistEntity c where c.projectId = :projectId")
    int deleteByProject(@Param("projectId") long projectId);
}
