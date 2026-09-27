package com.asmolabs.vectispire.core.threatintel.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * One CVE the CISA KEV catalogue lists, or listed. The EPSS scores are not here: they are FIRST's
 * file, stored whole in {@code t_epss_score} ({@link EpssScoreEntity}).
 */
@Entity
@Table(name = "t_threat_intel_feed")
public class ThreatIntelEntity {

    @Id
    @Column(name = "cve_id", length = 64, nullable = false)
    private String cveId;

    @Column(name = "is_kev", nullable = false)
    private boolean isKev;

    @Column(name = "date_added")
    private Instant dateAdded;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public String getCveId() {
        return cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    public boolean isKev() {
        return isKev;
    }

    public void setKev(boolean kev) {
        isKev = kev;
    }

    public Instant getDateAdded() {
        return dateAdded;
    }

    public void setDateAdded(Instant dateAdded) {
        this.dateAdded = dateAdded;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
