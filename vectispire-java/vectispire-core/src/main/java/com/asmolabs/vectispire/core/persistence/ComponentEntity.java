package com.asmolabs.vectispire.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One component a scan catalogued.
 *
 * <p><b>The inventory, not the backlog.</b> A row exists for every dependency the cataloguer saw,
 * whether or not anything is wrong with it — which is the whole point: the question "do we ship
 * this library, and in which version of which project" is asked on the day a vulnerability is
 * published, before any scanner knows about it, and the backlog is empty of exactly the
 * components nobody has flagged yet.
 */
@Entity
@Table(name = "t_component")
public class ComponentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "scan_id", nullable = false)
    private Long scanId;

    @Column(name = "name", length = 255, nullable = false)
    private String name;

    @Column(name = "version", length = 255)
    private String version;

    @Column(name = "purl", length = 500)
    private String purl;

    @Column(name = "type", length = 50)
    private String type;

    /** Null when the SBOM carried no dependency graph: unknown, not transitive. */
    @Column(name = "is_direct")
    private Boolean isDirect;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getScanId() {
        return scanId;
    }

    public void setScanId(Long scanId) {
        this.scanId = scanId;
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

    public Boolean getIsDirect() {
        return isDirect;
    }

    public void setIsDirect(Boolean isDirect) {
        this.isDirect = isDirect;
    }
}
