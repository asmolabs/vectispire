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
 * What a rule found for one line of one revision, at one instant, stored when something relies on it
 * — an answer resting on it, a submission, a sign-off (decision 0032 §6). <b>Never updated</b>: a
 * measurement is what was judged then, and a later one is another row; {@link
 * ChecklistMeasurementRepository} holds no update.
 */
@Entity
@Table(name = "t_checklist_measurement")
public class ChecklistMeasurementEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "checklist_id", nullable = false)
    private Long checklistId;

    @Column(name = "item_id", nullable = false)
    private Long itemId;

    /** {@code answer}, {@code submission} or {@code sign_off}: what relied on it. */
    @Column(name = "purpose", length = 20, nullable = false)
    private String purpose;

    @Column(name = "rule_kind", length = 40, nullable = false)
    private String ruleKind;

    @Column(name = "rule_digest", length = 64, nullable = false)
    private String ruleDigest;

    /** The canonical form of the rule applied, as the item held it. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "bound_rule", nullable = false)
    private String boundRule;

    @Column(name = "outcome", length = 10, nullable = false)
    private String outcome;

    @Column(name = "reason", length = 40)
    private String reason;

    @Column(name = "as_of")
    private Instant asOf;

    @Column(name = "computed_at", nullable = false)
    private Instant computedAt;

    @Column(name = "computed_by", length = 255, nullable = false)
    private String computedBy;

    @Column(name = "answer_id")
    private Long answerId;

    @Column(name = "answer_value", length = 20)
    private String answerValue;

    @Column(name = "reconciliation", length = 30)
    private String reconciliation;

    @Column(name = "evidence_digest", length = 64, nullable = false)
    private String evidenceDigest;

    /** The evidence as it was judged — {@code Measurement.evidenceJson()} — which its digest covers. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "evidence", nullable = false)
    private String evidence;

    public Long getId() {
        return id;
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

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    public String getRuleKind() {
        return ruleKind;
    }

    public void setRuleKind(String ruleKind) {
        this.ruleKind = ruleKind;
    }

    public String getRuleDigest() {
        return ruleDigest;
    }

    public void setRuleDigest(String ruleDigest) {
        this.ruleDigest = ruleDigest;
    }

    public String getBoundRule() {
        return boundRule;
    }

    public void setBoundRule(String boundRule) {
        this.boundRule = boundRule;
    }

    public String getOutcome() {
        return outcome;
    }

    public void setOutcome(String outcome) {
        this.outcome = outcome;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public Instant getAsOf() {
        return asOf;
    }

    public void setAsOf(Instant asOf) {
        this.asOf = asOf;
    }

    public Instant getComputedAt() {
        return computedAt;
    }

    public void setComputedAt(Instant computedAt) {
        this.computedAt = computedAt;
    }

    public String getComputedBy() {
        return computedBy;
    }

    public void setComputedBy(String computedBy) {
        this.computedBy = computedBy;
    }

    public Long getAnswerId() {
        return answerId;
    }

    public void setAnswerId(Long answerId) {
        this.answerId = answerId;
    }

    public String getAnswerValue() {
        return answerValue;
    }

    public void setAnswerValue(String answerValue) {
        this.answerValue = answerValue;
    }

    public String getReconciliation() {
        return reconciliation;
    }

    public void setReconciliation(String reconciliation) {
        this.reconciliation = reconciliation;
    }

    public String getEvidenceDigest() {
        return evidenceDigest;
    }

    public void setEvidenceDigest(String evidenceDigest) {
        this.evidenceDigest = evidenceDigest;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }
}
