package com.asmolabs.zanshin.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * One triage decision, as it happened.
 *
 * <p><b>Append-only by discipline, not by constraint.</b> Nothing in this codebase updates a row
 * of this table, and nothing should: the point of a history is that yesterday's entry says what
 * it said yesterday. A correction is a new decision, which is also how the person taking it
 * thinks about it.
 *
 * <p>The audit log remains the evidentiary record — hash-chained, verifiable. This is its
 * queryable counterpart: same facts, shaped so a report can join on them instead of reading
 * prose. See the changeset for why both exist.
 */
@Entity
@Table(name = "t_issue_triage_event")
public class TriageEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "issue_id", nullable = false)
    private Long issueId;

    @Column(name = "from_status", length = 30, nullable = false)
    private String fromStatus;

    @Column(name = "to_status", length = 30, nullable = false)
    private String toStatus;

    @Column(name = "justification", length = 64)
    private String justification;

    @Column(name = "comment")
    private String comment;

    /** Null when nobody decided: see {@link #origin}. */
    @Column(name = "actor", length = 255)
    private String actor;

    @Column(name = "origin", length = 20, nullable = false)
    private String origin;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    /** The target's last scan at that moment, hence the version the decision was taken against. */
    @Column(name = "scan_id")
    private Long scanId;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getIssueId() {
        return issueId;
    }

    public void setIssueId(Long issueId) {
        this.issueId = issueId;
    }

    public String getFromStatus() {
        return fromStatus;
    }

    public void setFromStatus(String fromStatus) {
        this.fromStatus = fromStatus;
    }

    public String getToStatus() {
        return toStatus;
    }

    public void setToStatus(String toStatus) {
        this.toStatus = toStatus;
    }

    public String getJustification() {
        return justification;
    }

    public void setJustification(String justification) {
        this.justification = justification;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getActor() {
        return actor;
    }

    public void setActor(String actor) {
        this.actor = actor;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public void setOccurredAt(Instant occurredAt) {
        this.occurredAt = occurredAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Long getScanId() {
        return scanId;
    }

    public void setScanId(Long scanId) {
        this.scanId = scanId;
    }
}
