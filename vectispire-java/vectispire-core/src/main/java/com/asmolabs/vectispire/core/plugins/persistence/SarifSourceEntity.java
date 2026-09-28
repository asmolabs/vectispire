package com.asmolabs.vectispire.core.plugins.persistence;

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
 * A declared internal source — of SARIF, and since decision 0032 of coverage and test reports: the
 * integration key it uploads with, the one project or repository it may deliver for, the report kinds
 * it may deliver, and the SARIF tools. The table keeps its first name: renaming it would be a
 * migration of its own for nothing a reader sees.
 *
 * <p>{@code apiKeyId} is unique: the key names the source, so an import never has to be told which
 * source it comes from — which is also why a caller cannot claim another source's name.
 */
@Entity
@Table(name = "t_sarif_source")
public class SarifSourceEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "slug", length = 40, nullable = false)
    private String slug;

    @Column(name = "name", length = 100, nullable = false)
    private String name;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "api_key_id", length = 36, nullable = false)
    private UUID apiKeyId;

    @Column(name = "project_id")
    private Long projectId;

    @Column(name = "repository_id")
    private Long repositoryId;

    /** The accepted tool names, lowercased, comma-separated — compared as {@code ToolKeys} compares them. */
    @Column(name = "tools", length = 1000, nullable = false)
    private String tools;

    /**
     * The report kinds it may deliver, comma-separated wire names ({@code SourceKind}). {@code sarif}
     * for every source declared before the column existed.
     */
    @Column(name = "kinds", length = 100, nullable = false)
    private String kinds;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "created_by", length = 255, nullable = false)
    private String createdBy;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSlug() {
        return slug;
    }

    public void setSlug(String slug) {
        this.slug = slug;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public UUID getApiKeyId() {
        return apiKeyId;
    }

    public void setApiKeyId(UUID apiKeyId) {
        this.apiKeyId = apiKeyId;
    }

    public Long getProjectId() {
        return projectId;
    }

    public void setProjectId(Long projectId) {
        this.projectId = projectId;
    }

    public Long getRepositoryId() {
        return repositoryId;
    }

    public void setRepositoryId(Long repositoryId) {
        this.repositoryId = repositoryId;
    }

    public String getTools() {
        return tools;
    }

    public void setTools(String tools) {
        this.tools = tools;
    }

    public String getKinds() {
        return kinds;
    }

    public void setKinds(String kinds) {
        this.kinds = kinds;
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
}
