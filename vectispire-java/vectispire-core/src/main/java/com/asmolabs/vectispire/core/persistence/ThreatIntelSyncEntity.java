package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

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
    private String status = "SYNCED";

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
        this.status = status != null ? status : "SYNCED";
    }
}
