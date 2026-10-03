package com.asmolabs.vectispire.core.checklists.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The items of the template versions, in each version's order. */
public interface ChecklistItemRepository extends JpaRepository<ChecklistItemEntity, Long> {

    List<ChecklistItemEntity> findByVersionIdOrderByPositionAsc(Long versionId);

    /**
     * The rules of one kind bound to the lines of the versions that project checklists answer, the superseded
     * revisions left out, a project once per line. {@code kindToken} is the canonical form's own writing of the
     * kind — {@code %"kind":"change_review"%}: keys sorted and no whitespace, so the text is matched, and each
     * row is still read as a rule by the caller. No {@code distinct}: MySQL compares a long text by its first
     * kilobyte only.
     */
    @Query("""
            select new com.asmolabs.vectispire.core.checklists.persistence.BoundRuleUse(c.projectId, i.boundRule)
              from ChecklistEntity c, ChecklistItemEntity i
             where i.versionId = c.templateVersionId and c.status <> :superseded and i.boundRule like :kindToken""")
    List<BoundRuleUse> boundInUse(@Param("superseded") String superseded, @Param("kindToken") String kindToken);

    /** A draft's items, before the ones its new layout or its new pairs read are written. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistItemEntity i where i.versionId = :versionId")
    int deleteByVersion(@Param("versionId") long versionId);
}
