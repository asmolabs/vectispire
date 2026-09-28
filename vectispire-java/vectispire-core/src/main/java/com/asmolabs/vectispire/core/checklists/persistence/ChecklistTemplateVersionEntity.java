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
 * One version of a template: the workbook it came from, the layout a person confirmed in it, and
 * who moved it through {@code draft}, {@code published} and {@code retired} (decision 0032 §3, §4).
 *
 * <p><b>The workbook's bytes are mapped with an explicit binary type, never {@code @Lob}</b>, which
 * Hibernate writes to PostgreSQL as an {@code oid} into {@code pg_largeobject} rather than into the
 * {@code bytea} column {@code ${bytes}} declares — and a deleted row would leave the object behind.
 * Listings do not load them: {@link ChecklistTemplateVersionRepository#summariesOf} selects every
 * column but this one.
 *
 * <p>The JSON columns hold what the service writes and reads back — the layout, the hand pairs and
 * the draft's authors — in forms {@code checklists} owns; nothing else reads them.
 */
@Entity
@Table(name = "t_checklist_template_version")
public class ChecklistTemplateVersionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "template_id", nullable = false)
    private Long templateId;

    @Column(name = "ordinal", nullable = false)
    private Integer ordinal;

    @Column(name = "label", length = 200)
    private String label;

    /** {@code draft}, {@code published} or {@code retired} — the wire names of {@code TemplateVersionStatus}. */
    @Column(name = "status", length = 20, nullable = false)
    private String status;

    /** Bumped by every edit and change of status, each a conditional update on the revision read. */
    @Column(name = "revision", nullable = false)
    private Integer revision;

    @Column(name = "source_sha256", length = 64, nullable = false)
    private String sourceSha256;

    @Column(name = "source_size", nullable = false)
    private Long sourceSize;

    @JdbcTypeCode(SqlTypes.LONGVARBINARY)
    @Column(name = "source_bytes", nullable = false)
    private byte[] sourceBytes;

    /** Null until a person has confirmed a layout: the reader only proposes one. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "layout")
    private String layout;

    @Column(name = "offers_not_applicable", nullable = false)
    private boolean offersNotApplicable;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "item_pairs")
    private String itemPairs;

    @Column(name = "previous_version_id")
    private Long previousVersionId;

    @Column(name = "derived_from_version_id")
    private Long derivedFromVersionId;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "draft_authors", nullable = false)
    private String draftAuthors;

    @Column(name = "imported_at", nullable = false)
    private Instant importedAt;

    @Column(name = "imported_by", length = 255, nullable = false)
    private String importedBy;

    @Column(name = "published_at")
    private Instant publishedAt;

    @Column(name = "published_by", length = 255)
    private String publishedBy;

    @Column(name = "retired_at")
    private Instant retiredAt;

    @Column(name = "retired_by", length = 255)
    private String retiredBy;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getTemplateId() {
        return templateId;
    }

    public void setTemplateId(Long templateId) {
        this.templateId = templateId;
    }

    public Integer getOrdinal() {
        return ordinal;
    }

    public void setOrdinal(Integer ordinal) {
        this.ordinal = ordinal;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Integer getRevision() {
        return revision;
    }

    public void setRevision(Integer revision) {
        this.revision = revision;
    }

    public String getSourceSha256() {
        return sourceSha256;
    }

    public void setSourceSha256(String sourceSha256) {
        this.sourceSha256 = sourceSha256;
    }

    public Long getSourceSize() {
        return sourceSize;
    }

    public void setSourceSize(Long sourceSize) {
        this.sourceSize = sourceSize;
    }

    public byte[] getSourceBytes() {
        return sourceBytes;
    }

    public void setSourceBytes(byte[] sourceBytes) {
        this.sourceBytes = sourceBytes;
    }

    public String getLayout() {
        return layout;
    }

    public void setLayout(String layout) {
        this.layout = layout;
    }

    public boolean isOffersNotApplicable() {
        return offersNotApplicable;
    }

    public void setOffersNotApplicable(boolean offersNotApplicable) {
        this.offersNotApplicable = offersNotApplicable;
    }

    public String getItemPairs() {
        return itemPairs;
    }

    public void setItemPairs(String itemPairs) {
        this.itemPairs = itemPairs;
    }

    public Long getPreviousVersionId() {
        return previousVersionId;
    }

    public void setPreviousVersionId(Long previousVersionId) {
        this.previousVersionId = previousVersionId;
    }

    public Long getDerivedFromVersionId() {
        return derivedFromVersionId;
    }

    public void setDerivedFromVersionId(Long derivedFromVersionId) {
        this.derivedFromVersionId = derivedFromVersionId;
    }

    public String getDraftAuthors() {
        return draftAuthors;
    }

    public void setDraftAuthors(String draftAuthors) {
        this.draftAuthors = draftAuthors;
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

    public Instant getPublishedAt() {
        return publishedAt;
    }

    public void setPublishedAt(Instant publishedAt) {
        this.publishedAt = publishedAt;
    }

    public String getPublishedBy() {
        return publishedBy;
    }

    public void setPublishedBy(String publishedBy) {
        this.publishedBy = publishedBy;
    }

    public Instant getRetiredAt() {
        return retiredAt;
    }

    public void setRetiredAt(Instant retiredAt) {
        this.retiredAt = retiredAt;
    }

    public String getRetiredBy() {
        return retiredBy;
    }

    public void setRetiredBy(String retiredBy) {
        this.retiredBy = retiredBy;
    }
}
