package com.asmolabs.vectispire.core.inventory.persistence;

import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface ApiContractRepository extends JpaRepository<ApiContractEntity, Long> {

    /**
     * The rows belonging to these repositories, and to no others.
     *
     * <p>Added for the global attack surface, which read every row and answered with all of
     * them: an API inventory is a map of somebody's exposed paths and methods, and a restricted
     * reader was being handed everybody's.
     */
    List<ApiContractEntity> findByRepositoryIdIn(Collection<Long> repositoryIds);

    List<ApiContractEntity> findByRepositoryIdOrderByCreatedAtDesc(Long repositoryId);

    List<ApiContractEntity> findByScanIdOrderByCreatedAtDesc(Long scanId);

    @org.springframework.data.jpa.repository.Modifying(clearAutomatically = true, flushAutomatically = true)
    @org.springframework.data.jpa.repository.Query("delete from ApiContractEntity c where (:repositoryId is not null and c.repositoryId = :repositoryId) or c.scanId = :scanId")
    @Transactional
    void deleteByRepositoryIdOrScanId(@org.springframework.data.repository.query.Param("repositoryId") Long repositoryId, @org.springframework.data.repository.query.Param("scanId") long scanId);

    @Transactional
    void deleteByScanId(long scanId);

    @Transactional
    void deleteByScanIdIn(Collection<Long> scanIds);

    @Transactional
    void deleteByRepositoryId(Long repositoryId);
}
