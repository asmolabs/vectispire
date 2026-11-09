package com.asmolabs.vectispire.core.plugins.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The packages of the accepted coverage imports that kept theirs. */
public interface CoveragePackageRepository extends JpaRepository<CoveragePackageEntity, Long> {

    /**
     * One import's packages, by path. One import at a time: an import holds up to ten thousand, and a
     * scoped measurement reads them repository by repository rather than a project's at once.
     */
    List<CoveragePackageEntity> findByImportIdOrderByPathAsc(long importId);

    /**
     * The packages of a repository's imports, before the imports themselves go: the subquery reaches
     * them through the import rows, so it must run while those still exist.
     */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from CoveragePackageEntity p where p.importId in "
            + "(select c.id from CoverageImportEntity c where c.repoId = :repositoryId)")
    int deleteByRepository(@Param("repositoryId") long repositoryId);
}
