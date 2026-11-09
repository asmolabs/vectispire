package com.asmolabs.vectispire.core.compliance.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * One month's compliance verdict for one framework, with the estate that produced it.
 *
 * <p>The reasoning is in the migration and in {@code ComplianceSnapshot}. What belongs here is the
 * storage decision: the estate's shape sits in columns rather than in a JSON document, because
 * "which months are comparable" is a question asked across rows, and a column is what lets an
 * engine answer it without learning to read JSON.
 */
@Entity
@Table(name = "t_compliance_snapshot")
public class ComplianceSnapshotEntity {

    /** {@code SqlTypes.CHAR} for the reason spelt out on {@code GateVerdictEntity}. */
    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "period", nullable = false, length = 7)
    private String period;

    @Column(name = "framework", nullable = false, length = 32)
    private String framework;

    @Column(name = "score", nullable = false)
    private int score;

    @Column(name = "status", nullable = false, length = 16)
    private String status;

    @Column(name = "targets", nullable = false)
    private int targets;

    @Column(name = "observed_targets", nullable = false)
    private int observedTargets;

    @Column(name = "fresh_targets", nullable = false)
    private int freshTargets;

    @Column(name = "freshness_days", nullable = false)
    private int freshnessDays;

    @Column(name = "eol_enabled", nullable = false)
    private boolean endOfLifeEnabled;

    @Column(name = "code_analysis_reaches", nullable = false)
    private boolean codeAnalysisReaches;

    @Column(name = "controls_total", nullable = false)
    private int controlsTotal;

    @Column(name = "controls_declared", nullable = false)
    private int controlsDeclared;

    @Column(name = "soa_findings", nullable = false)
    private int soaFindings;

    @Column(name = "captured_at", nullable = false)
    private Instant capturedAt;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getPeriod() {
        return period;
    }

    public void setPeriod(String period) {
        this.period = period;
    }

    public String getFramework() {
        return framework;
    }

    public void setFramework(String framework) {
        this.framework = framework;
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getTargets() {
        return targets;
    }

    public void setTargets(int targets) {
        this.targets = targets;
    }

    public int getObservedTargets() {
        return observedTargets;
    }

    public void setObservedTargets(int observedTargets) {
        this.observedTargets = observedTargets;
    }

    public int getFreshTargets() {
        return freshTargets;
    }

    public void setFreshTargets(int freshTargets) {
        this.freshTargets = freshTargets;
    }

    public int getFreshnessDays() {
        return freshnessDays;
    }

    public void setFreshnessDays(int freshnessDays) {
        this.freshnessDays = freshnessDays;
    }

    public boolean isEndOfLifeEnabled() {
        return endOfLifeEnabled;
    }

    public void setEndOfLifeEnabled(boolean endOfLifeEnabled) {
        this.endOfLifeEnabled = endOfLifeEnabled;
    }

    public boolean isCodeAnalysisReaches() {
        return codeAnalysisReaches;
    }

    public void setCodeAnalysisReaches(boolean codeAnalysisReaches) {
        this.codeAnalysisReaches = codeAnalysisReaches;
    }

    public int getControlsTotal() {
        return controlsTotal;
    }

    public void setControlsTotal(int controlsTotal) {
        this.controlsTotal = controlsTotal;
    }

    public int getControlsDeclared() {
        return controlsDeclared;
    }

    public void setControlsDeclared(int controlsDeclared) {
        this.controlsDeclared = controlsDeclared;
    }

    public int getSoaFindings() {
        return soaFindings;
    }

    public void setSoaFindings(int soaFindings) {
        this.soaFindings = soaFindings;
    }

    public Instant getCapturedAt() {
        return capturedAt;
    }

    public void setCapturedAt(Instant capturedAt) {
        this.capturedAt = capturedAt;
    }
}
