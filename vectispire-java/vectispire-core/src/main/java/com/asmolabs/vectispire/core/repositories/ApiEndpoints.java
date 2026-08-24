package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.ApiEndpointEntity;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ApiEndpoints extends JpaRepository<ApiEndpointEntity, Long> {

    List<ApiEndpointEntity> findByRepositoryIdOrderByPathAsc(Long repositoryId);

    List<ApiEndpointEntity> findByScanIdOrderByPathAsc(Long scanId);

    @Query("select e from ApiEndpointEntity e where e.scanId in :scanIds order by e.path asc")
    List<ApiEndpointEntity> findByScanIdIn(@Param("scanIds") Collection<Long> scanIds);

    @Query("select distinct e.framework from ApiEndpointEntity e where e.framework is not null")
    List<String> findDistinctFrameworks();

    void deleteByScanId(long scanId);

    void deleteByScanIdIn(Collection<Long> scanIds);
}
