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

    /** A draft's items, before the ones its new layout or its new pairs read are written. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistItemEntity i where i.versionId = :versionId")
    int deleteByVersion(@Param("versionId") long versionId);
}
