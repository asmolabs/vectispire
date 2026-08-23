package com.asmolabs.zanshin.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "t_license_policy")
public class LicensePolicyEntity {

    public static final Long SINGLETON_ID = 1L;

    @Id
    @Column(name = "id", nullable = false)
    private Long id = SINGLETON_ID;

    @Column(name = "disallowed_categories", length = 255, nullable = false)
    private String disallowedCategories = "STRONG_COPYLEFT,FORBIDDEN";

    @Column(name = "allowed_licenses")
    private String allowedLicenses = "";

    @Column(name = "disallowed_licenses")
    private String disallowedLicenses = "";

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getDisallowedCategories() {
        return disallowedCategories;
    }

    public void setDisallowedCategories(String disallowedCategories) {
        this.disallowedCategories = disallowedCategories != null ? disallowedCategories : "STRONG_COPYLEFT,FORBIDDEN";
    }

    public String getAllowedLicenses() {
        return allowedLicenses;
    }

    public void setAllowedLicenses(String allowedLicenses) {
        this.allowedLicenses = allowedLicenses != null ? allowedLicenses : "";
    }

    public String getDisallowedLicenses() {
        return disallowedLicenses;
    }

    public void setDisallowedLicenses(String disallowedLicenses) {
        this.disallowedLicenses = disallowedLicenses != null ? disallowedLicenses : "";
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
