package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.ApiContractEntity;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiContracts extends JpaRepository<ApiContractEntity, Long> {

    List<ApiContractEntity> findByRepositoryIdOrderByCreatedAtDesc(Long repositoryId);

    List<ApiContractEntity> findByScanIdOrderByCreatedAtDesc(Long scanId);

    @org.springframework.data.jpa.repository.Modifying(clearAutomatically = true, flushAutomatically = true)
    @org.springframework.data.jpa.repository.Query("delete from ApiContractEntity c where (:repositoryId is not null and c.repositoryId = :repositoryId) or c.scanId = :scanId")
    void deleteByRepositoryIdOrScanId(@org.springframework.data.repository.query.Param("repositoryId") Long repositoryId, @org.springframework.data.repository.query.Param("scanId") long scanId);

    void deleteByScanId(long scanId);

    void deleteByScanIdIn(Collection<Long> scanIds);

    void deleteByRepositoryId(Long repositoryId);
}
