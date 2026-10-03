package com.asmolabs.vectispire.core.reportplugins.persistence;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/** Every manifest each report plugin ever had, by digest. */
public interface ReportPluginManifestRepository extends JpaRepository<ReportPluginManifestEntity, String> {

    /** A plugin's manifests, newest first — its history, bounded by how often its governor registers one. */
    List<ReportPluginManifestEntity> findByPluginIdOrderByRegisteredAtDescDigestAsc(String pluginId);

    /** The manifests of these plugins, for a listing that reads them in one statement rather than one each. */
    List<ReportPluginManifestEntity> findByPluginIdInOrderByRegisteredAtDescDigestAsc(Collection<String> pluginIds);

    Optional<ReportPluginManifestEntity> findByDigestAndPluginId(String digest, String pluginId);
}
