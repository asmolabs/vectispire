package com.asmolabs.zanshin.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Singleton configuration row for SOC/SIEM streaming integrations.
 */
@Entity
@Table(name = "t_siem_config")
public class SiemConfigEntity {

    public static final Long SINGLETON_ID = 1L;

    @Id
    @Column(name = "id", nullable = false)
    private Long id = SINGLETON_ID;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = false;

    @Column(name = "protocol", length = 16, nullable = false)
    private String protocol = "WEBHOOK";

    @Column(name = "endpoint", length = 1024)
    private String endpoint;

    @Column(name = "auth_header", length = 512)
    private String authHeader;

    @Column(name = "min_severity", length = 32, nullable = false)
    private String minSeverity = "HIGH";

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol != null ? protocol : "WEBHOOK";
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getAuthHeader() {
        return authHeader;
    }

    public void setAuthHeader(String authHeader) {
        this.authHeader = authHeader;
    }

    public String getMinSeverity() {
        return minSeverity;
    }

    public void setMinSeverity(String minSeverity) {
        this.minSeverity = minSeverity != null ? minSeverity : "HIGH";
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
