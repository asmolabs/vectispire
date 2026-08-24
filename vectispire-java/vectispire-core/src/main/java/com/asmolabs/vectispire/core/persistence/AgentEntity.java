package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A registered scan executor.
 *
 * <p>{@code sealingPublicKey} is what lets a deployment key travel to it end to end: the
 * control plane seals the key for this agent alone, so an agent that claims a scan it is not
 * entitled to cannot open it.
 */
@Entity
@Table(name = "t_agent")
public class AgentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "name", length = 255, nullable = false)
    private String name;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "kind", length = 20, nullable = false)
    private String kind;

    @Column(name = "labels", length = 255)
    private String labels;

    @Column(name = "credentials_mode", length = 20, nullable = false)
    private String credentialsMode;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @Column(name = "max_concurrent")
    private Integer maxConcurrent;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "api_key_id")
    private UUID apiKeyId;

    @Column(name = "hostname", length = 255)
    private String hostname;

    @Column(name = "platform", length = 255)
    private String platform;

    @Column(name = "version", length = 50)
    private String version;

    @Column(name = "scanner_engine", length = 50)
    private String scannerEngine;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "capabilities")
    private String capabilities;

    @Column(name = "contract_version", length = 20)
    private String contractVersion;

    @Column(name = "sealing_public_key", length = 255)
    private String sealingPublicKey;

    @Column(name = "last_seen_at")
    private Instant lastSeenAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getKind() {
        return kind;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public String getLabels() {
        return labels;
    }

    public void setLabels(String labels) {
        this.labels = labels;
    }

    public String getCredentialsMode() {
        return credentialsMode;
    }

    public void setCredentialsMode(String credentialsMode) {
        this.credentialsMode = credentialsMode;
    }

    public boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Integer getMaxConcurrent() {
        return maxConcurrent;
    }

    public void setMaxConcurrent(Integer maxConcurrent) {
        this.maxConcurrent = maxConcurrent;
    }

    public UUID getApiKeyId() {
        return apiKeyId;
    }

    public void setApiKeyId(UUID apiKeyId) {
        this.apiKeyId = apiKeyId;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = platform;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getScannerEngine() {
        return scannerEngine;
    }

    public void setScannerEngine(String scannerEngine) {
        this.scannerEngine = scannerEngine;
    }

    public String getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(String capabilities) {
        this.capabilities = capabilities;
    }

    public String getContractVersion() {
        return contractVersion;
    }

    public void setContractVersion(String contractVersion) {
        this.contractVersion = contractVersion;
    }

    public String getSealingPublicKey() {
        return sealingPublicKey;
    }

    public void setSealingPublicKey(String sealingPublicKey) {
        this.sealingPublicKey = sealingPublicKey;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
