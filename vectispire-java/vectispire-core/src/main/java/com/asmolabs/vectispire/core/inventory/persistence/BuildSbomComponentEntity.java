package com.asmolabs.vectispire.core.inventory.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One component a build SBOM listed, kept so that every later scan of its repository is completed by it
 * while it is the newest — not only the scan that was newest when it arrived.
 */
@Entity
@Table(name = "t_build_sbom_component")
public class BuildSbomComponentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "import_id", nullable = false)
    private Long importId;

    @Column(name = "name", length = 255, nullable = false)
    private String name;

    /** Null where the build states none. */
    @Column(name = "version", length = 255)
    private String version;

    /** Canonical ({@code BuildSbom.canonicalPurl}), or null. */
    @Column(name = "purl", length = 500)
    private String purl;

    @Column(name = "type", length = 50)
    private String type;

    /** The licences the build declared, joined by {@code OR}, or null. */
    @Column(name = "license", length = 255)
    private String license;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getImportId() {
        return importId;
    }

    public void setImportId(Long importId) {
        this.importId = importId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getPurl() {
        return purl;
    }

    public void setPurl(String purl) {
        this.purl = purl;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getLicense() {
        return license;
    }

    public void setLicense(String license) {
        this.license = license;
    }
}
