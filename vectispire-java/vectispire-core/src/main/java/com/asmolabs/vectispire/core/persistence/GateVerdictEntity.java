package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import java.time.Instant;
import java.util.UUID;

/**
 * One answer the gate gave, kept so the answer can be shown later.
 *
 * <p><b>Why a row exists at all.</b> The gate used to store its policies and nothing else, so
 * "every target passes" could mean the estate is clean or the gate has never stopped anything —
 * two opposite readings of the same sentence. A control whose refusals cannot be exhibited is
 * not a demonstrated control; this table is what turns the claim into a register.
 *
 * <p><b>{@code evaluated} is kept beside {@code violations} on purpose.</b> A verdict that passed
 * after examining four hundred issues and one that passed after examining none look identical
 * once reduced to {@code passed}. Only the first is evidence of anything.
 *
 * <p>The policy that produced the verdict is recorded by source and version rather than copied:
 * the policy itself is versioned in its own table, and duplicating its fields here would create a
 * second truth that drifts. What is stored is enough to say <em>which</em> policy applied, and
 * the severity threshold, which is the field a reader asks about first.
 */
@Entity
@Table(name = "t_gate_verdict")
public class GateVerdictEntity {

    /**
     * <b>{@code SqlTypes.CHAR}, like every other UUID key here.</b> Left to its default, Hibernate
     * expects {@code binary(16)} on MySQL while the migration writes {@code char(36)} — and the
     * two disagree only on that one engine, so the unit suite on SQLite and the campaign on
     * PostgreSQL both pass while MySQL refuses to start at all.
     */
    @Id
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "repo_id")
    private Long repoId;

    @Column(name = "container_id")
    private Long containerId;

    @Column(name = "passed", nullable = false)
    private boolean passed;

    @Column(name = "evaluated", nullable = false)
    private int evaluated;

    @Column(name = "violations", nullable = false)
    private int violations;

    @Column(name = "critical_count", nullable = false)
    private long criticalCount;

    @Column(name = "high_count", nullable = false)
    private long highCount;

    @Column(name = "medium_count", nullable = false)
    private long mediumCount;

    @Column(name = "low_count", nullable = false)
    private long lowCount;

    @Column(name = "fail_on_severity", length = 20)
    private String failOnSeverity;

    @Column(name = "policy_source", length = 32, nullable = false)
    private String policySource;

    @Column(name = "policy_version")
    private Long policyVersion;

    /**
     * Whether the caller asked for a looser policy than the stored one and was refused.
     *
     * <p>A caller may only tighten a gate, never relax it — that rule is enforced elsewhere and
     * tested. Recording the attempt is what makes the rule <em>visible</em>: an integration that
     * keeps asking to be let through is a conversation somebody should have, and it leaves no
     * other trace.
     */
    @Column(name = "relaxations_ignored", nullable = false)
    private boolean relaxationsIgnored;

    @Column(name = "decided_at", nullable = false)
    private Instant decidedAt;

    @Column(name = "decided_by", length = 255)
    private String decidedBy;

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Long getRepoId() {
        return repoId;
    }

    public void setRepoId(Long repoId) {
        this.repoId = repoId;
    }

    public Long getContainerId() {
        return containerId;
    }

    public void setContainerId(Long containerId) {
        this.containerId = containerId;
    }

    public boolean isPassed() {
        return passed;
    }

    public void setPassed(boolean passed) {
        this.passed = passed;
    }

    public int getEvaluated() {
        return evaluated;
    }

    public void setEvaluated(int evaluated) {
        this.evaluated = evaluated;
    }

    public int getViolations() {
        return violations;
    }

    public void setViolations(int violations) {
        this.violations = violations;
    }

    public long getCriticalCount() {
        return criticalCount;
    }

    public void setCriticalCount(long criticalCount) {
        this.criticalCount = criticalCount;
    }

    public long getHighCount() {
        return highCount;
    }

    public void setHighCount(long highCount) {
        this.highCount = highCount;
    }

    public long getMediumCount() {
        return mediumCount;
    }

    public void setMediumCount(long mediumCount) {
        this.mediumCount = mediumCount;
    }

    public long getLowCount() {
        return lowCount;
    }

    public void setLowCount(long lowCount) {
        this.lowCount = lowCount;
    }

    public String getFailOnSeverity() {
        return failOnSeverity;
    }

    public void setFailOnSeverity(String failOnSeverity) {
        this.failOnSeverity = failOnSeverity;
    }

    public String getPolicySource() {
        return policySource;
    }

    public void setPolicySource(String policySource) {
        this.policySource = policySource;
    }

    public Long getPolicyVersion() {
        return policyVersion;
    }

    public void setPolicyVersion(Long policyVersion) {
        this.policyVersion = policyVersion;
    }

    public boolean isRelaxationsIgnored() {
        return relaxationsIgnored;
    }

    public void setRelaxationsIgnored(boolean relaxationsIgnored) {
        this.relaxationsIgnored = relaxationsIgnored;
    }

    public Instant getDecidedAt() {
        return decidedAt;
    }

    public void setDecidedAt(Instant decidedAt) {
        this.decidedAt = decidedAt;
    }

    public String getDecidedBy() {
        return decidedBy;
    }

    public void setDecidedBy(String decidedBy) {
        this.decidedBy = decidedBy;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
}
