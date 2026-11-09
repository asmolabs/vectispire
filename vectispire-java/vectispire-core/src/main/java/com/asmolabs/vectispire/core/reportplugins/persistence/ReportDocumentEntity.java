package com.asmolabs.vectispire.core.reportplugins.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * The package of a produced report run (decision 0035 §3): the plugin's file once it passed its type's check, its
 * detached signature and the signed provenance, as the zip a recipient downloads — apart from the run, so that no
 * listing of runs reads up to an output's 50 MiB a row. Purged past the evidence window; the run keeps the
 * output's and the package's digests.
 */
@Entity
@Table(name = "t_report_document")
public class ReportDocumentEntity {

    @Id
    @Column(name = "run_id", nullable = false)
    private Long runId;

    @JdbcTypeCode(SqlTypes.LONGVARBINARY)
    @Column(name = "content", nullable = false)
    private byte[] content;

    @Column(name = "sha256", length = 64, nullable = false)
    private String sha256;

    @Column(name = "size_bytes", nullable = false)
    private Long sizeBytes;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public Long getRunId() {
        return runId;
    }

    public void setRunId(Long runId) {
        this.runId = runId;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public Long getSizeBytes() {
        return sizeBytes;
    }

    public void setSizeBytes(Long sizeBytes) {
        this.sizeBytes = sizeBytes;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
