package com.asmolabs.zanshin.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * A monitored container image.
 */
@Entity
@Table(name = "t_container")
public class ContainerEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "registry", length = 255)
    private String registry;

    @Column(name = "image_name", length = 255, nullable = false)
    private String imageName;

    @Column(name = "tag", length = 255, nullable = false)
    private String tag;

    @Column(name = "scan_interval_minutes")
    private Integer scanIntervalMinutes;

    @Column(name = "scan_cron", length = 255)
    private String scanCron;

    @Column(name = "required_agent_label", length = 255)
    private String requiredAgentLabel;

    @Column(name = "last_scheduled_scan_at")
    private Instant lastScheduledScanAt;

    @Column(name = "tier", length = 32, nullable = false)
    private String tier = "TIER_2_BUSINESS_OPERATIONAL";

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRegistry() {
        return registry;
    }

    public void setRegistry(String registry) {
        this.registry = registry;
    }

    public String getImageName() {
        return imageName;
    }

    public void setImageName(String imageName) {
        this.imageName = imageName;
    }

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }

    public Integer getScanIntervalMinutes() {
        return scanIntervalMinutes;
    }

    public void setScanIntervalMinutes(Integer scanIntervalMinutes) {
        this.scanIntervalMinutes = scanIntervalMinutes;
    }

    public String getScanCron() {
        return scanCron;
    }

    public void setScanCron(String scanCron) {
        this.scanCron = scanCron;
    }

    public String getRequiredAgentLabel() {
        return requiredAgentLabel;
    }

    public void setRequiredAgentLabel(String requiredAgentLabel) {
        this.requiredAgentLabel = requiredAgentLabel;
    }

    public Instant getLastScheduledScanAt() {
        return lastScheduledScanAt;
    }

    public void setLastScheduledScanAt(Instant lastScheduledScanAt) {
        this.lastScheduledScanAt = lastScheduledScanAt;
    }

    public String getTier() {
        return tier;
    }

    public void setTier(String tier) {
        this.tier = tier != null ? tier : "TIER_2_BUSINESS_OPERATIONAL";
    }
}
