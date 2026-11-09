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
 * The versions of the checklist templates.
 *
 * <p><b>Every change to a version is a conditional statement on the revision its writer read</b>,
 * whose row count names the winner — never a {@code save} of the row read earlier, which lets
 * whoever writes last win. Two people editing one draft, an edit racing its publication, two
 * publications of one draft: in each, one statement matches and the other matches nothing, and its
 * caller refuses rather than writing over what it did not see.
 */
public interface ChecklistTemplateVersionRepository extends JpaRepository<ChecklistTemplateVersionEntity, Long> {

    Optional<ChecklistTemplateVersionEntity> findByTemplateIdAndOrdinal(Long templateId, Integer ordinal);

    boolean existsByTemplateIdAndStatus(Long templateId, String status);

    @Query("select coalesce(max(v.ordinal), 0) from ChecklistTemplateVersionEntity v where v.templateId = :templateId")
    int lastOrdinal(@Param("templateId") long templateId);

    /** The versions ever published — published or retired since — newest first. */
    @Query("select v.id from ChecklistTemplateVersionEntity v"
            + " where v.templateId = :templateId and v.publishedAt is not null order by v.ordinal desc")
    List<Long> publishedNewestFirst(@Param("templateId") long templateId);

    /** Every version of a template, oldest first, without its workbook. */
    @Query("select new com.asmolabs.vectispire.core.checklists.persistence.ChecklistTemplateVersionSummary("
            + "v.id, v.templateId, v.ordinal, v.label, v.status, v.revision, v.sourceSha256, v.sourceSize, v.layout,"
            + " v.offersNotApplicable, v.previousVersionId, v.derivedFromVersionId, v.draftAuthors, v.importedAt,"
            + " v.importedBy,"
            + " v.publishedAt, v.publishedBy, v.retiredAt, v.retiredBy,"
            + " (select count(i) from ChecklistItemEntity i where i.versionId = v.id))"
            + " from ChecklistTemplateVersionEntity v where v.templateId = :templateId order by v.ordinal asc")
    List<ChecklistTemplateVersionSummary> summariesOf(@Param("templateId") long templateId);

    /** A draft's edit — its layout, its pairs, who wrote it — if it is still the draft its writer read. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ChecklistTemplateVersionEntity v set v.revision = v.revision + 1, v.layout = :layout,"
            + " v.offersNotApplicable = :offersNotApplicable, v.itemPairs = :itemPairs, v.draftAuthors = :draftAuthors"
            + " where v.id = :id and v.status = :draft and v.revision = :revision")
    int editDraft(
            @Param("id") long id,
            @Param("revision") int revision,
            @Param("draft") String draft,
            @Param("layout") String layout,
            @Param("offersNotApplicable") boolean offersNotApplicable,
            @Param("itemPairs") String itemPairs,
            @Param("draftAuthors") String draftAuthors);

    /** Publishes a draft, if it is still at the revision its publisher reviewed. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ChecklistTemplateVersionEntity v set v.status = :published, v.revision = v.revision + 1,"
            + " v.publishedAt = :at, v.publishedBy = :by"
            + " where v.id = :id and v.status = :draft and v.revision = :revision")
    int publish(
            @Param("id") long id,
            @Param("revision") int revision,
            @Param("draft") String draft,
            @Param("published") String published,
            @Param("at") Instant at,
            @Param("by") String by);

    /** Retires a version — a published one, or a draft set aside — if it is still as it was read. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ChecklistTemplateVersionEntity v set v.status = :retired, v.revision = v.revision + 1,"
            + " v.retiredAt = :at, v.retiredBy = :by"
            + " where v.id = :id and v.status = :from and v.revision = :revision")
    int retire(
            @Param("id") long id,
            @Param("revision") int revision,
            @Param("from") String from,
            @Param("retired") String retired,
            @Param("at") Instant at,
            @Param("by") String by);
}
