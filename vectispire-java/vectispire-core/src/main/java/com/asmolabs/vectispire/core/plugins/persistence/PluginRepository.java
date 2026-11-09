package com.asmolabs.vectispire.core.plugins.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** The registered plugins. */
public interface PluginRepository extends JpaRepository<PluginEntity, String> {

    List<PluginEntity> findAllByOrderByIdAsc();

    /**
     * The enabled plugins switched on for a project — what a scan of one of its repositories runs.
     * A disabled plugin keeps its activations, so enabling it again restores them as they were.
     */
    @Query("""
            select p from PluginEntity p, PluginActivationEntity a
             where a.pluginId = p.id and a.projectId = :projectId and p.enabled = true
             order by p.id""")
    List<PluginEntity> enabledForProject(@Param("projectId") long projectId);
}
