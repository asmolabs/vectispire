package com.asmolabs.vectispire.core.plugins.persistence;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/** Every manifest a plugin ever had, by digest. Rows are inserted, never updated. */
public interface PluginManifestRepository extends JpaRepository<PluginManifestEntity, String> {

    /** By both halves of a task's reference: a digest under another plugin's id is not this plugin. */
    Optional<PluginManifestEntity> findByDigestAndPluginId(String digest, String pluginId);
}
