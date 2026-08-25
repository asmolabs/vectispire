package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.ApiContractEntity;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiContracts extends JpaRepository<ApiContractEntity, Long> {

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
    void deleteByRepositoryIdOrScanId(@org.springframework.data.repository.query.Param("repositoryId") Long repositoryId, @org.springframework.data.repository.query.Param("scanId") long scanId);

    void deleteByScanId(long scanId);

    void deleteByScanIdIn(Collection<Long> scanIds);

    void deleteByRepositoryId(Long repositoryId);
}
