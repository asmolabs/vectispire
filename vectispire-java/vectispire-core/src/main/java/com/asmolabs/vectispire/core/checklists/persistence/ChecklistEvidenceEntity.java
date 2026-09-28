package com.asmolabs.vectispire.core.checklists.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * A proof attached to one line of a checklist: a link, or a file whose bytes are a {@link
 * ChecklistFileEntity} (decision 0032 §5). Withdrawn, never deleted; the withdrawal is dated and
 * attributed. {@code performedOn} and {@code validUntil} are days, kept as the instant their UTC day
 * starts.
 */
@Entity
@Table(name = "t_checklist_evidence")
public class ChecklistEvidenceEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "checklist_id", nullable = false)
    private Long checklistId;

    @Column(name = "item_id", nullable = false)
    private Long itemId;

    /** {@code link} or {@code file}. */
    @Column(name = "kind", length = 10, nullable = false)
    private String kind;

    @Column(name = "link", length = 2000)
    private String link;

    @Column(name = "file_id")
    private Long fileId;

    @Column(name = "file_name", length = 255)
    private String fileName;

    /** As the uploader declared it: stored, shown, and never used to decide how the file is served. */
    @Column(name = "media_type", length = 255)
    private String mediaType;

    @Column(name = "file_size")
    private Long fileSize;

    @Column(name = "file_sha256", length = 64)
    private String fileSha256;

    @Column(name = "performed_on", nullable = false)
    private Instant performedOn;

    @Column(name = "valid_until")
    private Instant validUntil;

    @Column(name = "added_by", length = 255, nullable = false)
    private String addedBy;

    @Column(name = "added_by_id", nullable = false)
    private Long addedById;

    @Column(name = "added_at", nullable = false)
    private Instant addedAt;

    @Column(name = "carried_from_id")
    private Long carriedFromId;

    @Column(name = "carried_by_id")
    private Long carriedById;

    @Column(name = "edition", nullable = false)
    private Integer edition;

    @Column(name = "withdrawn_by", length = 255)
    private String withdrawnBy;

    @Column(name = "withdrawn_by_id")
    private Long withdrawnById;

    @Column(name = "withdrawn_at")
    private Instant withdrawnAt;

    @Column(name = "withdrawn_edition")
    private Integer withdrawnEdition;

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

    public Long getItemId() {
        return itemId;
    }

    public void setItemId(Long itemId) {
        this.itemId = itemId;
    }

    public String getKind() {
        return kind;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public Long getFileId() {
        return fileId;
    }

    public void setFileId(Long fileId) {
        this.fileId = fileId;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getMediaType() {
        return mediaType;
    }

    public void setMediaType(String mediaType) {
        this.mediaType = mediaType;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }

    public String getFileSha256() {
        return fileSha256;
    }

    public void setFileSha256(String fileSha256) {
        this.fileSha256 = fileSha256;
    }

    public Instant getPerformedOn() {
        return performedOn;
    }

    public void setPerformedOn(Instant performedOn) {
        this.performedOn = performedOn;
    }

    public Instant getValidUntil() {
        return validUntil;
    }

    public void setValidUntil(Instant validUntil) {
        this.validUntil = validUntil;
    }

    public String getAddedBy() {
        return addedBy;
    }

    public void setAddedBy(String addedBy) {
        this.addedBy = addedBy;
    }

    public Long getAddedById() {
        return addedById;
    }

    public void setAddedById(Long addedById) {
        this.addedById = addedById;
    }

    public Instant getAddedAt() {
        return addedAt;
    }

    public void setAddedAt(Instant addedAt) {
        this.addedAt = addedAt;
    }

    public Long getCarriedFromId() {
        return carriedFromId;
    }

    public void setCarriedFromId(Long carriedFromId) {
        this.carriedFromId = carriedFromId;
    }

    public Long getCarriedById() {
        return carriedById;
    }

    public void setCarriedById(Long carriedById) {
        this.carriedById = carriedById;
    }

    public Integer getEdition() {
        return edition;
    }

    public void setEdition(Integer edition) {
        this.edition = edition;
    }

    public String getWithdrawnBy() {
        return withdrawnBy;
    }

    public void setWithdrawnBy(String withdrawnBy) {
        this.withdrawnBy = withdrawnBy;
    }

    public Long getWithdrawnById() {
        return withdrawnById;
    }

    public void setWithdrawnById(Long withdrawnById) {
        this.withdrawnById = withdrawnById;
    }

    public Instant getWithdrawnAt() {
        return withdrawnAt;
    }

    public void setWithdrawnAt(Instant withdrawnAt) {
        this.withdrawnAt = withdrawnAt;
    }

    public Integer getWithdrawnEdition() {
        return withdrawnEdition;
    }

    public void setWithdrawnEdition(Integer withdrawnEdition) {
        this.withdrawnEdition = withdrawnEdition;
    }
}
