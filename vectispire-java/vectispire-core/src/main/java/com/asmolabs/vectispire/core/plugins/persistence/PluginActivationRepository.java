package com.asmolabs.vectispire.core.plugins.persistence;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** Which projects each plugin analyses. */
public interface PluginActivationRepository extends JpaRepository<PluginActivationEntity, Long> {

    List<PluginActivationEntity> findByProjectIdOrderByPluginIdAsc(long projectId);

    List<PluginActivationEntity> findByPluginIdOrderByProjectIdAsc(String pluginId);

    Optional<PluginActivationEntity> findByPluginIdAndProjectId(String pluginId, long projectId);

    /** Every activation of a project that is going away — its listener's, in the deleting transaction. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from PluginActivationEntity a where a.projectId = :projectId")
    int deleteByProject(@Param("projectId") long projectId);
}
