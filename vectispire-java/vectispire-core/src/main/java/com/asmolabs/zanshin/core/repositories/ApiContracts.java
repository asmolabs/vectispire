package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.ApiContractEntity;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiContracts extends JpaRepository<ApiContractEntity, Long> {

    List<ApiContractEntity> findByRepositoryIdOrderByCreatedAtDesc(Long repositoryId);

    List<ApiContractEntity> findByScanIdOrderByCreatedAtDesc(Long scanId);

    void deleteByScanId(long scanId);

    void deleteByScanIdIn(Collection<Long> scanIds);
}
