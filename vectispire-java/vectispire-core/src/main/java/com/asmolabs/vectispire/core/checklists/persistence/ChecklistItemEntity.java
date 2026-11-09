package com.asmolabs.vectispire.core.checklists.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * One line of a template version, in the template's words as imported (decision 0032 §2).
 *
 * <p>{@code itemKey} and {@code contentDigest} are a data contract: a project's answers follow the
 * key into the next version, and the digest decides whether they arrive as current or to be
 * confirmed. Both are computed by {@code ChecklistItem} in {@code common.domain}, never here.
 */
@Entity
@Table(name = "t_checklist_item")
public class ChecklistItemEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "version_id", nullable = false)
    private Long versionId;

    @Column(name = "item_key", length = 255, nullable = false)
    private String itemKey;

    @Column(name = "item_position", nullable = false)
    private Integer position;

    @Column(name = "domain", length = 1000, nullable = false)
    private String domain;

    @Column(name = "objective", length = 1000, nullable = false)
    private String objective;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "control", nullable = false)
    private String control;

    @Column(name = "contact", length = 255, nullable = false)
    private String contact;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "kpi", nullable = false)
    private String kpi;

    @Column(name = "content_digest", length = 64, nullable = false)
    private String contentDigest;

    @Column(name = "sheet_row", nullable = false)
    private Integer sheetRow;

    @Column(name = "evidence_kind", length = 20, nullable = false)
    private String evidenceKind;

    @Column(name = "evidence_validity_months")
    private Integer evidenceValidityMonths;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "bound_rule")
    private String boundRule;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getVersionId() {
        return versionId;
    }

    public void setVersionId(Long versionId) {
        this.versionId = versionId;
    }

    public String getItemKey() {
        return itemKey;
    }

    public void setItemKey(String itemKey) {
        this.itemKey = itemKey;
    }

    public Integer getPosition() {
        return position;
    }

    public void setPosition(Integer position) {
        this.position = position;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getObjective() {
        return objective;
    }

    public void setObjective(String objective) {
        this.objective = objective;
    }

    public String getControl() {
        return control;
    }

    public void setControl(String control) {
        this.control = control;
    }

    public String getContact() {
        return contact;
    }

    public void setContact(String contact) {
        this.contact = contact;
    }

    public String getKpi() {
        return kpi;
    }

    public void setKpi(String kpi) {
        this.kpi = kpi;
    }

    public String getContentDigest() {
        return contentDigest;
    }

    public void setContentDigest(String contentDigest) {
        this.contentDigest = contentDigest;
    }

    public Integer getSheetRow() {
        return sheetRow;
    }

    public void setSheetRow(Integer sheetRow) {
        this.sheetRow = sheetRow;
    }

    public String getEvidenceKind() {
        return evidenceKind;
    }

    public void setEvidenceKind(String evidenceKind) {
        this.evidenceKind = evidenceKind;
    }

    public Integer getEvidenceValidityMonths() {
        return evidenceValidityMonths;
    }

    public void setEvidenceValidityMonths(Integer evidenceValidityMonths) {
        this.evidenceValidityMonths = evidenceValidityMonths;
    }

    public String getBoundRule() {
        return boundRule;
    }

    public void setBoundRule(String boundRule) {
        this.boundRule = boundRule;
    }
}
