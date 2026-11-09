package com.asmolabs.vectispire.core.inventory.persistence;

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
 * One accepted build SBOM: which declared source and key sent it, what it declared, and the document's
 * SHA-256 — the inventory a scan is completed with is the pipeline's word, and this binds the word to a
 * key and to the bytes it sent.
 *
 * <p>The commit and the branch are the pipeline's statement. The branch decides which scans the SBOM
 * completes — a feature branch's build does not speak for the branch a target scans; the commit is kept
 * and compared with nothing, scans recording none.
 */
@Entity
@Table(name = "t_build_sbom")
public class BuildSbomEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "source_id", nullable = false)
    private Long sourceId;

    @Column(name = "source_slug", length = 40, nullable = false)
    private String sourceSlug;

    @Column(name = "repo_id", nullable = false)
    private Long repoId;

    /** {@code 1.4}, {@code 1.5} or {@code 1.6}. */
    @Column(name = "spec_version", length = 10, nullable = false)
    private String specVersion;

    /** The tool that wrote the document, as its metadata names it, or null. */
    @Column(name = "tool", length = 200)
    private String tool;

    @Column(name = "components_count", nullable = false)
    private Integer componentsCount;

    @Column(name = "commit_sha", length = 64)
    private String commit;

    @Column(name = "branch_name", length = 255)
    private String branch;

    @Column(name = "document_sha256", length = 64, nullable = false)
    private String documentSha256;

    @Column(name = "imported_at", nullable = false)
    private Instant importedAt;

    @Column(name = "imported_by", length = 255, nullable = false)
    private String importedBy;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "api_key_id", length = 36, nullable = false)
    private UUID apiKeyId;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getSourceId() {
        return sourceId;
    }

    public void setSourceId(Long sourceId) {
        this.sourceId = sourceId;
    }

    public String getSourceSlug() {
        return sourceSlug;
    }

    public void setSourceSlug(String sourceSlug) {
        this.sourceSlug = sourceSlug;
    }

    public Long getRepoId() {
        return repoId;
    }

    public void setRepoId(Long repoId) {
        this.repoId = repoId;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public void setSpecVersion(String specVersion) {
        this.specVersion = specVersion;
    }

    public String getTool() {
        return tool;
    }

    public void setTool(String tool) {
        this.tool = tool;
    }

    public Integer getComponentsCount() {
        return componentsCount;
    }

    public void setComponentsCount(Integer componentsCount) {
        this.componentsCount = componentsCount;
    }

    public String getCommit() {
        return commit;
    }

    public void setCommit(String commit) {
        this.commit = commit;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public String getDocumentSha256() {
        return documentSha256;
    }

    public void setDocumentSha256(String documentSha256) {
        this.documentSha256 = documentSha256;
    }

    public Instant getImportedAt() {
        return importedAt;
    }

    public void setImportedAt(Instant importedAt) {
        this.importedAt = importedAt;
    }

    public String getImportedBy() {
        return importedBy;
    }

    public void setImportedBy(String importedBy) {
        this.importedBy = importedBy;
    }

    public UUID getApiKeyId() {
        return apiKeyId;
    }

    public void setApiKeyId(UUID apiKeyId) {
        this.apiKeyId = apiKeyId;
    }
}
