package com.asmolabs.vectispire.core.checklists.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * A project's checklist profile linked to an account (decision 0044): one row per project and profile,
 * replaced by the next link, deleted by an unlinking and by the project's deletion. The account is an id
 * and nothing more — whether it still exists, is active and has an address is read when it matters.
 */
@Entity
@Table(name = "t_checklist_contact")
public class ChecklistContactEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    /** The profile's key, as {@code ContactProfiles} keys it. */
    @Column(name = "profile", length = 255, nullable = false)
    private String profile;

    @Column(name = "account_id", nullable = false)
    private Long accountId;

    @Column(name = "linked_by", length = 255, nullable = false)
    private String linkedBy;

    @Column(name = "linked_at", nullable = false)
    private Instant linkedAt;

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

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public Long getAccountId() {
        return accountId;
    }

    public void setAccountId(Long accountId) {
        this.accountId = accountId;
    }

    public String getLinkedBy() {
        return linkedBy;
    }

    public void setLinkedBy(String linkedBy) {
        this.linkedBy = linkedBy;
    }

    public Instant getLinkedAt() {
        return linkedAt;
    }

    public void setLinkedAt(Instant linkedAt) {
        this.linkedAt = linkedAt;
    }
}
