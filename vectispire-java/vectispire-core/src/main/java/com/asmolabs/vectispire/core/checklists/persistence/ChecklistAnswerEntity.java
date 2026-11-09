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
 * One answer to one line of a checklist, <b>never updated</b> (decision 0032 §5): answering again
 * inserts a row, the current answer is the newest per item, and the line's history is every row.
 * {@link ChecklistAnswerRepository} holds no update statement, which is what keeps it so.
 *
 * <p>{@code answeredBy} and {@code answeredAt} are the person who gave the answer and when. A copy
 * carried into another revision keeps them, points at the row it came from, and names who carried
 * it beside them (§4).
 *
 * <p>{@code answeredByKind} says whether a person wrote it or Vectispire did, from a measurement
 * ({@code AnswerAuthor}): a system answer names no account, so {@code answeredById} is null for it and
 * only for it — a check constraint holds the two together (V56). {@code withdrawn} marks the row by
 * which Vectispire withdraws its own answer: the line then has no current answer, and the history keeps
 * what was withdrawn.
 */
@Entity
@Table(name = "t_checklist_answer")
public class ChecklistAnswerEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "checklist_id", nullable = false)
    private Long checklistId;

    @Column(name = "item_id", nullable = false)
    private Long itemId;

    /** {@code yes}, {@code no} or {@code not_applicable} — the wire names of {@code ChecklistAnswer}. */
    @Column(name = "answer_value", length = 20, nullable = false)
    private String value;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "answer_comment")
    private String comment;

    @Column(name = "answered_by", length = 255, nullable = false)
    private String answeredBy;

    /** The account that answered; null for an answer Vectispire wrote, which is no account's. */
    @Column(name = "answered_by_id")
    private Long answeredById;

    /** {@code person} or {@code system} — the wire names of {@code AnswerAuthor}. */
    @Column(name = "answered_by_kind", length = 10, nullable = false)
    private String answeredByKind;

    @Column(name = "answered_at", nullable = false)
    private Instant answeredAt;

    @Column(name = "measurement_id")
    private Long measurementId;

    @Column(name = "carried_from_id")
    private Long carriedFromId;

    @Column(name = "carried_by", length = 255)
    private String carriedBy;

    @Column(name = "carried_by_id")
    private Long carriedById;

    @Column(name = "carried_at")
    private Instant carriedAt;

    @Column(name = "needs_confirmation", nullable = false)
    private boolean needsConfirmation;

    @Column(name = "withdrawn", nullable = false)
    private boolean withdrawn;

    @Column(name = "edition", nullable = false)
    private Integer edition;

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

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getAnsweredBy() {
        return answeredBy;
    }

    public void setAnsweredBy(String answeredBy) {
        this.answeredBy = answeredBy;
    }

    public Long getAnsweredById() {
        return answeredById;
    }

    public void setAnsweredById(Long answeredById) {
        this.answeredById = answeredById;
    }

    public String getAnsweredByKind() {
        return answeredByKind;
    }

    public void setAnsweredByKind(String answeredByKind) {
        this.answeredByKind = answeredByKind;
    }

    public boolean isWithdrawn() {
        return withdrawn;
    }

    public void setWithdrawn(boolean withdrawn) {
        this.withdrawn = withdrawn;
    }

    public Instant getAnsweredAt() {
        return answeredAt;
    }

    public void setAnsweredAt(Instant answeredAt) {
        this.answeredAt = answeredAt;
    }

    public Long getMeasurementId() {
        return measurementId;
    }

    public void setMeasurementId(Long measurementId) {
        this.measurementId = measurementId;
    }

    public Long getCarriedFromId() {
        return carriedFromId;
    }

    public void setCarriedFromId(Long carriedFromId) {
        this.carriedFromId = carriedFromId;
    }

    public String getCarriedBy() {
        return carriedBy;
    }

    public void setCarriedBy(String carriedBy) {
        this.carriedBy = carriedBy;
    }

    public Long getCarriedById() {
        return carriedById;
    }

    public void setCarriedById(Long carriedById) {
        this.carriedById = carriedById;
    }

    public Instant getCarriedAt() {
        return carriedAt;
    }

    public void setCarriedAt(Instant carriedAt) {
        this.carriedAt = carriedAt;
    }

    public boolean isNeedsConfirmation() {
        return needsConfirmation;
    }

    public void setNeedsConfirmation(boolean needsConfirmation) {
        this.needsConfirmation = needsConfirmation;
    }

    public Integer getEdition() {
        return edition;
    }

    public void setEdition(Integer edition) {
        this.edition = edition;
    }
}
