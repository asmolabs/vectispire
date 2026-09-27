package com.asmolabs.vectispire.core.plugins.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * One version of a plugin's manifest, keyed by its digest and never rewritten.
 *
 * <p>The digest is computed from the manifest ({@code PluginManifest.digest}), so the key and the
 * content cannot disagree; a row is inserted once and read by every executor a task sends there.
 */
@Entity
@Table(name = "t_plugin_manifest")
public class PluginManifestEntity {

    @Id
    @Column(name = "digest", length = 64, nullable = false)
    private String digest;

    @Column(name = "plugin_id", length = 40, nullable = false)
    private String pluginId;

    /** The manifest as JSON, in the form a governor registers and an agent receives. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "manifest", nullable = false)
    private String manifest;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

    public String getPluginId() {
        return pluginId;
    }

    public void setPluginId(String pluginId) {
        this.pluginId = pluginId;
    }

    public String getManifest() {
        return manifest;
    }

    public void setManifest(String manifest) {
        this.manifest = manifest;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
