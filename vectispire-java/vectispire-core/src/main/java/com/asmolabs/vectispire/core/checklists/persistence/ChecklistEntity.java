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
 * One revision of a project's answers against one template version (decision 0032 §2, §5).
 *
 * <p>{@code revision} numbers a project's checklists and is what the routes name; {@code edition}
 * counts the writes to this one, and every write is a conditional statement on the edition its
 * writer read ({@link ChecklistRepository}). {@code openSlot} is 1 while the revision is a draft or
 * submitted and null otherwise, which the key {@code (project_id, open_slot)} turns into "at most one
 * open checklist per project".
 */
@Entity
@Table(name = "t_checklist")
public class ChecklistEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Column(name = "template_version_id", nullable = false)
    private Long templateVersionId;

    @Column(name = "revision", nullable = false)
    private Integer revision;

    /** {@code draft}, {@code submitted}, {@code signed_off} or {@code superseded}. */
    @Column(name = "status", length = 20, nullable = false)
    private String status;

    @Column(name = "edition", nullable = false)
    private Integer edition;

    @Column(name = "open_slot")
    private Integer openSlot;

    @Column(name = "author_id", nullable = false)
    private Long authorId;

    @Column(name = "author", length = 255, nullable = false)
    private String author;

    @Column(name = "opened_at", nullable = false)
    private Instant openedAt;

    @Column(name = "opened_by", length = 255, nullable = false)
    private String openedBy;

    @Column(name = "supersedes_id")
    private Long supersedesId;

    @Column(name = "submitted_at")
    private Instant submittedAt;

    @Column(name = "submitted_by", length = 255)
    private String submittedBy;

    @Column(name = "submitted_by_id")
    private Long submittedById;

    @Column(name = "returned_at")
    private Instant returnedAt;

    @Column(name = "returned_by", length = 255)
    private String returnedBy;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "return_reason")
    private String returnReason;

    @Column(name = "signed_off_at")
    private Instant signedOffAt;

    @Column(name = "signed_off_by", length = 255)
    private String signedOffBy;

    @Column(name = "signed_off_by_id")
    private Long signedOffById;

    @Column(name = "sign_off_four_eyes")
    private Boolean signOffFourEyes;

    @Column(name = "superseded_at")
    private Instant supersededAt;

    @Column(name = "superseded_by", length = 255)
    private String supersededBy;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getProjectId() {
        return projectId;
    }

    public void setProjectId(Long projectId) {
        this.projectId = projectId;
    }

    public Long getTemplateVersionId() {
        return templateVersionId;
    }

    public void setTemplateVersionId(Long templateVersionId) {
        this.templateVersionId = templateVersionId;
    }

    public Integer getRevision() {
        return revision;
    }

    public void setRevision(Integer revision) {
        this.revision = revision;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Integer getEdition() {
        return edition;
    }

    public void setEdition(Integer edition) {
        this.edition = edition;
    }

    public Integer getOpenSlot() {
        return openSlot;
    }

    public void setOpenSlot(Integer openSlot) {
        this.openSlot = openSlot;
    }

    public Long getAuthorId() {
        return authorId;
    }

    public void setAuthorId(Long authorId) {
        this.authorId = authorId;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public Instant getOpenedAt() {
        return openedAt;
    }

    public void setOpenedAt(Instant openedAt) {
        this.openedAt = openedAt;
    }

    public String getOpenedBy() {
        return openedBy;
    }

    public void setOpenedBy(String openedBy) {
        this.openedBy = openedBy;
    }

    public Long getSupersedesId() {
        return supersedesId;
    }

    public void setSupersedesId(Long supersedesId) {
        this.supersedesId = supersedesId;
    }

    public Instant getSubmittedAt() {
        return submittedAt;
    }

    public void setSubmittedAt(Instant submittedAt) {
        this.submittedAt = submittedAt;
    }

    public String getSubmittedBy() {
        return submittedBy;
    }

    public void setSubmittedBy(String submittedBy) {
        this.submittedBy = submittedBy;
    }

    public Long getSubmittedById() {
        return submittedById;
    }

    public void setSubmittedById(Long submittedById) {
        this.submittedById = submittedById;
    }

    public Instant getReturnedAt() {
        return returnedAt;
    }

    public void setReturnedAt(Instant returnedAt) {
        this.returnedAt = returnedAt;
    }

    public String getReturnedBy() {
        return returnedBy;
    }

    public void setReturnedBy(String returnedBy) {
        this.returnedBy = returnedBy;
    }

    public String getReturnReason() {
        return returnReason;
    }

    public void setReturnReason(String returnReason) {
        this.returnReason = returnReason;
    }

    public Instant getSignedOffAt() {
        return signedOffAt;
    }

    public void setSignedOffAt(Instant signedOffAt) {
        this.signedOffAt = signedOffAt;
    }

    public String getSignedOffBy() {
        return signedOffBy;
    }

    public void setSignedOffBy(String signedOffBy) {
        this.signedOffBy = signedOffBy;
    }

    public Long getSignedOffById() {
        return signedOffById;
    }

    public void setSignedOffById(Long signedOffById) {
        this.signedOffById = signedOffById;
    }

    public Boolean getSignOffFourEyes() {
        return signOffFourEyes;
    }

    public void setSignOffFourEyes(Boolean signOffFourEyes) {
        this.signOffFourEyes = signOffFourEyes;
    }

    public Instant getSupersededAt() {
        return supersededAt;
    }

    public void setSupersededAt(Instant supersededAt) {
        this.supersededAt = supersededAt;
    }

    public String getSupersededBy() {
        return supersededBy;
    }

    public void setSupersededBy(String supersededBy) {
        this.supersededBy = supersededBy;
    }
}
