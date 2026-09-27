package com.asmolabs.vectispire.core.plugins.persistence;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The accepted SARIF imports. */
public interface SarifImportRepository extends JpaRepository<SarifImportEntity, Long> {

    List<SarifImportEntity> findByRepoIdOrderByImportedAtDescIdDesc(long repoId, Pageable page);

    /** A repository's imports, when the repository goes — its listener's, in the deleting transaction. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from SarifImportEntity i where i.repoId = :repositoryId")
    int deleteByRepository(@Param("repositoryId") long repositoryId);
}
