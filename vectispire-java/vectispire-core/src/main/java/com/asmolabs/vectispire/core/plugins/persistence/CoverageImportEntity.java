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
 * One accepted coverage report: what it counted for the whole repository, which declared source and
 * key sent it, and the document's SHA-256 — the figure a checklist reads is the pipeline's word, and
 * this is what binds the word to a key and a document.
 *
 * <p>The branch counts are null when the report counted no branch, which is not 0 of 0. The commit
 * and the branch are what the pipeline stated, kept as its word and verified against nothing.
 */
@Entity
@Table(name = "t_coverage_import")
public class CoverageImportEntity {

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

    /** {@code jacoco}, {@code cobertura} or {@code lcov} — as declared, never sniffed. */
    @Column(name = "format", length = 20, nullable = false)
    private String format;

    @Column(name = "tool_version", length = 100)
    private String toolVersion;

    @Column(name = "lines_covered", nullable = false)
    private long linesCovered;

    @Column(name = "lines_total", nullable = false)
    private long linesTotal;

    @Column(name = "branches_covered")
    private Long branchesCovered;

    @Column(name = "branches_total")
    private Long branchesTotal;

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

    /**
     * {@code kept}, or why the report's packages were not — {@code CoveragePackages.State}; null for an
     * import accepted before packages were kept (V71), which kept none.
     */
    @Column(name = "packages_state", length = 20)
    private String packagesState;

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

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getToolVersion() {
        return toolVersion;
    }

    public void setToolVersion(String toolVersion) {
        this.toolVersion = toolVersion;
    }

    public long getLinesCovered() {
        return linesCovered;
    }

    public void setLinesCovered(long linesCovered) {
        this.linesCovered = linesCovered;
    }

    public long getLinesTotal() {
        return linesTotal;
    }

    public void setLinesTotal(long linesTotal) {
        this.linesTotal = linesTotal;
    }

    public Long getBranchesCovered() {
        return branchesCovered;
    }

    public void setBranchesCovered(Long branchesCovered) {
        this.branchesCovered = branchesCovered;
    }

    public Long getBranchesTotal() {
        return branchesTotal;
    }

    public void setBranchesTotal(Long branchesTotal) {
        this.branchesTotal = branchesTotal;
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

    public String getPackagesState() {
        return packagesState;
    }

    public void setPackagesState(String packagesState) {
        this.packagesState = packagesState;
    }
}
