package com.asmolabs.vectispire.core.threatintel.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * The one row saying where the CISA KEV catalogue stands — see {@code ThreatIntelSyncStatus} for
 * what each column means to a reader.
 */
@Entity
@Table(name = "t_threat_intel_sync")
public class ThreatIntelSyncEntity {

    public static final Long SINGLETON_ID = 1L;

    @Id
    @Column(name = "id", nullable = false)
    private Long id = SINGLETON_ID;

    @Column(name = "last_synced_at")
    private Instant lastSyncedAt;

    @Column(name = "cve_count", nullable = false)
    private long cveCount = 0;

    @Column(name = "kev_count", nullable = false)
    private long kevCount = 0;

    @Column(name = "status", length = 32, nullable = false)
    private String status = "NEVER_SYNCED";

    @Column(name = "kev_catalog_version", length = 32)
    private String kevCatalogVersion;

    @Column(name = "kev_released_at")
    private Instant kevReleasedAt;

    @Column(name = "last_attempt_at")
    private Instant lastAttemptAt;

    @Column(name = "last_error", length = 500)
    private String lastError;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Instant getLastSyncedAt() {
        return lastSyncedAt;
    }

    public void setLastSyncedAt(Instant lastSyncedAt) {
        this.lastSyncedAt = lastSyncedAt;
    }

    public long getCveCount() {
        return cveCount;
    }

    public void setCveCount(long cveCount) {
        this.cveCount = cveCount;
    }

    public long getKevCount() {
        return kevCount;
    }

    public void setKevCount(long kevCount) {
        this.kevCount = kevCount;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status != null ? status : "NEVER_SYNCED";
    }

    public String getKevCatalogVersion() {
        return kevCatalogVersion;
    }

    public void setKevCatalogVersion(String kevCatalogVersion) {
        this.kevCatalogVersion = kevCatalogVersion;
    }

    public Instant getKevReleasedAt() {
        return kevReleasedAt;
    }

    public void setKevReleasedAt(Instant kevReleasedAt) {
        this.kevReleasedAt = kevReleasedAt;
    }

    public Instant getLastAttemptAt() {
        return lastAttemptAt;
    }

    public void setLastAttemptAt(Instant lastAttemptAt) {
        this.lastAttemptAt = lastAttemptAt;
    }

    public String getLastError() {
        return lastError;
    }

    public void setLastError(String lastError) {
        this.lastError = lastError;
    }
}
