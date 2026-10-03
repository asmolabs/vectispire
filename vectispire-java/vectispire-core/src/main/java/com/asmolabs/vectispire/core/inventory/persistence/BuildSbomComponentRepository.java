package com.asmolabs.vectispire.core.inventory.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The components of the accepted build SBOMs. */
public interface BuildSbomComponentRepository extends JpaRepository<BuildSbomComponentEntity, Long> {

    /** One import's components, in the document's order. */
    List<BuildSbomComponentEntity> findByImportIdOrderByIdAsc(long importId);

    /** The children of these imports, before the imports — the caller hands at most a thousand. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from BuildSbomComponentEntity c where c.importId in :importIds")
    int deleteByImportIds(@Param("importIds") List<Long> importIds);
}
