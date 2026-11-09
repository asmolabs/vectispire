package com.asmolabs.vectispire.core.plugins.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * A registered plugin: its id — the slug in every one of its issues' fingerprints, hence the key
 * and never changed — and the manifest the next scan runs.
 *
 * <p>The manifest itself is not here. Every version is kept in {@link PluginManifestEntity}, by
 * digest, because a task queued before an update names the older one and its executor must fetch
 * exactly that.
 */
@Entity
@Table(name = "t_plugin")
public class PluginEntity {

    @Id
    @Column(name = "id", length = 40, nullable = false)
    private String id;

    @Column(name = "name", length = 100, nullable = false)
    private String name;

    @Column(name = "manifest_digest", length = 64, nullable = false)
    private String manifestDigest;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "created_by", length = 255, nullable = false)
    private String createdBy;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "updated_by", length = 255, nullable = false)
    private String updatedBy;

    /**
     * The governor's justification for running this plugin although its manifest declares no signer,
     * or null for no waiver (V60, decision 0017 §9.1).
     */
    @Column(name = "unsigned_waiver", length = 500)
    private String unsignedWaiver;

    @Column(name = "unsigned_waived_by", length = 255)
    private String unsignedWaivedBy;

    @Column(name = "unsigned_waived_at")
    private Instant unsignedWaivedAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getManifestDigest() {
        return manifestDigest;
    }

    public void setManifestDigest(String manifestDigest) {
        this.manifestDigest = manifestDigest;
    }

    public boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    public String getUnsignedWaiver() {
        return unsignedWaiver;
    }

    public void setUnsignedWaiver(String unsignedWaiver) {
        this.unsignedWaiver = unsignedWaiver;
    }

    public String getUnsignedWaivedBy() {
        return unsignedWaivedBy;
    }

    public void setUnsignedWaivedBy(String unsignedWaivedBy) {
        this.unsignedWaivedBy = unsignedWaivedBy;
    }

    public Instant getUnsignedWaivedAt() {
        return unsignedWaivedAt;
    }

    public void setUnsignedWaivedAt(Instant unsignedWaivedAt) {
        this.unsignedWaivedAt = unsignedWaivedAt;
    }
}
