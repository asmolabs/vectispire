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
 * One accepted SARIF import: the dated record an imported issue has where a scanned one has its
 * scan. The source is named by id and by slug — the slug survives the source's deletion, and it is
 * what an auditor reads.
 */
@Entity
@Table(name = "t_sarif_import")
public class SarifImportEntity {

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

    /** The tools the document declared, {@code name version}, comma-separated. */
    @Column(name = "tools", length = 1000, nullable = false)
    private String tools;

    /**
     * The tool keys whose runs the import accepted — {@code import:<source>/<tool>}, sorted, comma-
     * separated — what a checklist reads to know the tool produced (decision 0032 §6). Null for an import
     * accepted before the column existed: which of its tools ran was never written down, and a reader
     * must not infer it from {@code tools}, which is the document's words, clipped.
     */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "tool_keys")
    private String toolKeys;

    @Column(name = "document_sha256", length = 64, nullable = false)
    private String documentSha256;

    @Column(name = "results_count", nullable = false)
    private int resultsCount;

    @Column(name = "created_count", nullable = false)
    private int createdCount;

    @Column(name = "resolved_count", nullable = false)
    private int resolvedCount;

    @Column(name = "reopened_count", nullable = false)
    private int reopenedCount;

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

    public String getTools() {
        return tools;
    }

    public String getToolKeys() {
        return toolKeys;
    }

    public void setToolKeys(String toolKeys) {
        this.toolKeys = toolKeys;
    }

    public void setTools(String tools) {
        this.tools = tools;
    }

    public String getDocumentSha256() {
        return documentSha256;
    }

    public void setDocumentSha256(String documentSha256) {
        this.documentSha256 = documentSha256;
    }

    public int getResultsCount() {
        return resultsCount;
    }

    public void setResultsCount(int resultsCount) {
        this.resultsCount = resultsCount;
    }

    public int getCreatedCount() {
        return createdCount;
    }

    public void setCreatedCount(int createdCount) {
        this.createdCount = createdCount;
    }

    public int getResolvedCount() {
        return resolvedCount;
    }

    public void setResolvedCount(int resolvedCount) {
        this.resolvedCount = resolvedCount;
    }

    public int getReopenedCount() {
        return reopenedCount;
    }

    public void setReopenedCount(int reopenedCount) {
        this.reopenedCount = reopenedCount;
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
