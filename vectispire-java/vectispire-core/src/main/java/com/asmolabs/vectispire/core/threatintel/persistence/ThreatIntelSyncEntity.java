package com.asmolabs.vectispire.core.threatintel.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * The one row saying where the CISA KEV catalogue and FIRST's EPSS file stand — see {@code
 * ThreatIntelSyncStatus} for what each column means to a reader. The {@code epss_} columns are the
 * EPSS feed's own: the two are fetched, refused and retried apart.
 *
 * <p><b>The KEV synchronisation saves this row whole, which is safe only in the order it does it</b>:
 * it takes the row's write lock first ({@code markAttempt}) and reads the row after, so an EPSS claim
 * or result either committed before that read or waits for the save's commit — never overwritten by
 * values read before it. Reading the row before marking the attempt would put back EPSS columns an
 * EPSS synchronisation had just written. The EPSS feed itself writes only through conditional updates
 * of its own columns ({@code ThreatIntelSyncRepository}).
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

    @Column(name = "epss_status", length = 32, nullable = false)
    private String epssStatus = "NEVER_SYNCED";

    @Column(name = "epss_synced_at")
    private Instant epssSyncedAt;

    @Column(name = "epss_model_version", length = 32)
    private String epssModelVersion;

    @Column(name = "epss_score_date")
    private Instant epssScoreDate;

    @Column(name = "epss_count", nullable = false)
    private long epssCount = 0;

    /** The generation of {@code t_epss_score} in use; null until a file was applied. */
    @Column(name = "epss_generation")
    private Long epssGeneration;

    @Column(name = "epss_attempt_at")
    private Instant epssAttemptAt;

    /** Until when the synchronisation that holds the claim may keep it. */
    @Column(name = "epss_lease_until")
    private Instant epssLeaseUntil;

    /** The generation the synchronisation holding the lease is writing. */
    @Column(name = "epss_claim")
    private Long epssClaim;

    @Column(name = "epss_error", length = 500)
    private String epssError;

    public String getEpssStatus() {
        return epssStatus;
    }

    public void setEpssStatus(String epssStatus) {
        this.epssStatus = epssStatus != null ? epssStatus : "NEVER_SYNCED";
    }

    public Instant getEpssSyncedAt() {
        return epssSyncedAt;
    }

    public void setEpssSyncedAt(Instant epssSyncedAt) {
        this.epssSyncedAt = epssSyncedAt;
    }

    public String getEpssModelVersion() {
        return epssModelVersion;
    }

    public void setEpssModelVersion(String epssModelVersion) {
        this.epssModelVersion = epssModelVersion;
    }

    public Instant getEpssScoreDate() {
        return epssScoreDate;
    }

    public void setEpssScoreDate(Instant epssScoreDate) {
        this.epssScoreDate = epssScoreDate;
    }

    public long getEpssCount() {
        return epssCount;
    }

    public void setEpssCount(long epssCount) {
        this.epssCount = epssCount;
    }

    public Long getEpssGeneration() {
        return epssGeneration;
    }

    public void setEpssGeneration(Long epssGeneration) {
        this.epssGeneration = epssGeneration;
    }

    public Instant getEpssAttemptAt() {
        return epssAttemptAt;
    }

    public void setEpssAttemptAt(Instant epssAttemptAt) {
        this.epssAttemptAt = epssAttemptAt;
    }

    public Instant getEpssLeaseUntil() {
        return epssLeaseUntil;
    }

    public void setEpssLeaseUntil(Instant epssLeaseUntil) {
        this.epssLeaseUntil = epssLeaseUntil;
    }

    public Long getEpssClaim() {
        return epssClaim;
    }

    public void setEpssClaim(Long epssClaim) {
        this.epssClaim = epssClaim;
    }

    public String getEpssError() {
        return epssError;
    }

    public void setEpssError(String epssError) {
        this.epssError = epssError;
    }

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
