package com.asmolabs.vectispire.core.forges.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * How changes reach one branch of one repository target, as its forge said at the last reading (decision 0037, lot
 * G3) — the evidence of the checklists' {@code change_review} rule. One row per repository and branch, written again
 * at each reading. No foreign key to the target, which is another module's row: the readings go with the target
 * through {@code TargetDeleted}, and with the connection when it is deleted.
 */
@Entity
@Table(name = "t_forge_review_reading")
public class ForgeReviewReadingEntity {

    /** The rule's branch when it names none: the default branch the forge names. */
    public static final String DEFAULT_BRANCH = "";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "repository_id", nullable = false)
    private Long repositoryId;

    @Column(name = "wanted_branch", length = 255, nullable = false)
    private String wantedBranch;

    @Column(name = "state", length = 20, nullable = false)
    private String state;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "connection_id")
    private UUID connectionId;

    @Column(name = "forge_id", length = 64)
    private String forgeId;

    @Column(name = "window_days", nullable = false)
    private Integer windowDays;

    @Column(name = "read_at")
    private Instant readAt;

    @Column(name = "reason", length = 1000)
    private String reason;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "evidence")
    private String evidence;

    @Column(name = "evidence_sha256", length = 64)
    private String evidenceSha256;

    @Column(name = "claimed_until")
    private Instant claimedUntil;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getRepositoryId() {
        return repositoryId;
    }

    public void setRepositoryId(Long repositoryId) {
        this.repositoryId = repositoryId;
    }

    public String getWantedBranch() {
        return wantedBranch;
    }

    public void setWantedBranch(String wantedBranch) {
        this.wantedBranch = wantedBranch;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public UUID getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(UUID connectionId) {
        this.connectionId = connectionId;
    }

    public String getForgeId() {
        return forgeId;
    }

    public void setForgeId(String forgeId) {
        this.forgeId = forgeId;
    }

    public Integer getWindowDays() {
        return windowDays;
    }

    public void setWindowDays(Integer windowDays) {
        this.windowDays = windowDays;
    }

    public Instant getReadAt() {
        return readAt;
    }

    public void setReadAt(Instant readAt) {
        this.readAt = readAt;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getEvidenceSha256() {
        return evidenceSha256;
    }

    public void setEvidenceSha256(String evidenceSha256) {
        this.evidenceSha256 = evidenceSha256;
    }

    public Instant getClaimedUntil() {
        return claimedUntil;
    }

    public void setClaimedUntil(Instant claimedUntil) {
        this.claimedUntil = claimedUntil;
    }
}
