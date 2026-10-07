package com.asmolabs.vectispire.core.settings.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Whether one integration is switched on (decision 0040). The table knows no list: which keys exist is
 * the domain's {@code Integration.all()}, and a key without a row reads disabled — see V83.
 */
@Entity
@Table(name = "t_integration")
public class IntegrationEntity {

    @Id
    @Column(name = "integration_key", length = 64, nullable = false)
    private String key;

    @Column(name = "enabled", nullable = false)
    private Boolean enabled;

    /** Null for a row nobody has changed since V83 seeded it. */
    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "updated_by", length = 255)
    private String updatedBy;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
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
}
