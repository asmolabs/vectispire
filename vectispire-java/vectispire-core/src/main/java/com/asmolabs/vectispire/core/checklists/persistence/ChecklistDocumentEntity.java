package com.asmolabs.vectispire.core.checklists.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A signed-off revision's document, rendered and signed inside its sign-off (decision 0032 §10): the
 * package as the route serves it, and the digests and signatures of its two parts. Written once, never
 * updated; its one delete is its project's.
 *
 * <p>The bytes are mapped with an explicit binary type, never {@code @Lob}, which PostgreSQL would store
 * as an {@code oid} a deleted row leaves behind — see {@code ChecklistTemplateVersionEntity}. Only the
 * document route reads a row of it, by its revision.
 */
@Entity
@Table(name = "t_checklist_document")
public class ChecklistDocumentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "checklist_id", nullable = false)
    private Long checklistId;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @JdbcTypeCode(SqlTypes.LONGVARBINARY)
    @Column(name = "content", nullable = false)
    private byte[] content;

    @Column(name = "size_bytes", nullable = false)
    private Long sizeBytes;

    @Column(name = "sha256", length = 64, nullable = false)
    private String sha256;

    @Column(name = "workbook_sha256", length = 64, nullable = false)
    private String workbookSha256;

    @Column(name = "workbook_signature", length = 255, nullable = false)
    private String workbookSignature;

    @Column(name = "statement_sha256", length = 64, nullable = false)
    private String statementSha256;

    @Column(name = "statement_signature", length = 255, nullable = false)
    private String statementSignature;

    @Column(name = "signing_key_id", length = 128, nullable = false)
    private String signingKeyId;

    @Column(name = "product_version", length = 100)
    private String productVersion;

    @Column(name = "produced_at", nullable = false)
    private Instant producedAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getChecklistId() {
        return checklistId;
    }

    public void setChecklistId(Long checklistId) {
        this.checklistId = checklistId;
    }

    public Long getProjectId() {
        return projectId;
    }

    public void setProjectId(Long projectId) {
        this.projectId = projectId;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public Long getSizeBytes() {
        return sizeBytes;
    }

    public void setSizeBytes(Long sizeBytes) {
        this.sizeBytes = sizeBytes;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getWorkbookSha256() {
        return workbookSha256;
    }

    public void setWorkbookSha256(String workbookSha256) {
        this.workbookSha256 = workbookSha256;
    }

    public String getWorkbookSignature() {
        return workbookSignature;
    }

    public void setWorkbookSignature(String workbookSignature) {
        this.workbookSignature = workbookSignature;
    }

    public String getStatementSha256() {
        return statementSha256;
    }

    public void setStatementSha256(String statementSha256) {
        this.statementSha256 = statementSha256;
    }

    public String getStatementSignature() {
        return statementSignature;
    }

    public void setStatementSignature(String statementSignature) {
        this.statementSignature = statementSignature;
    }

    public String getSigningKeyId() {
        return signingKeyId;
    }

    public void setSigningKeyId(String signingKeyId) {
        this.signingKeyId = signingKeyId;
    }

    public String getProductVersion() {
        return productVersion;
    }

    public void setProductVersion(String productVersion) {
        this.productVersion = productVersion;
    }

    public Instant getProducedAt() {
        return producedAt;
    }

    public void setProducedAt(Instant producedAt) {
        this.producedAt = producedAt;
    }
}
