package com.asmolabs.vectispire.core.inventory.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

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

    /**
     * The scan's target and creation instant, copied from it when the row is written (V61) so that no
     * read of the inventory joins {@code scanning}'s table. Both are facts a scan never changes, and the
     * row goes with its scan, so the copy cannot disagree with it.
     */
    @Column(name = "repo_id")
    private Long repoId;

    @Column(name = "container_id")
    private Long containerId;

    @Column(name = "scan_created_at")
    private Instant scanCreatedAt;

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

    /**
     * Who listed the row (V82): null for the scanner, {@code build} or {@code both} once a build SBOM
     * completed the scan — {@code ComponentOrigin}. For {@code both}, {@link #version} and {@link #purl}
     * are the build's and {@link #scannedVersion} and {@link #scannedPurl} the scanner's, which a later
     * SBOM no longer listing the package gives back.
     */
    @Column(name = "origin", length = 10)
    private String origin;

    /** The import that completed the row, or null: a reference only, the import leaving by the evidence window. */
    @Column(name = "build_sbom_id")
    private Long buildSbomId;

    @Column(name = "scanned_version", length = 255)
    private String scannedVersion;

    @Column(name = "scanned_purl", length = 500)
    private String scannedPurl;

    /** The licence the build declared; the scanner's own are read from its SBOM. */
    @Column(name = "declared_license", length = 255)
    private String declaredLicense;

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

    public Instant getScanCreatedAt() {
        return scanCreatedAt;
    }

    public void setScanCreatedAt(Instant scanCreatedAt) {
        this.scanCreatedAt = scanCreatedAt;
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

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public Long getBuildSbomId() {
        return buildSbomId;
    }

    public void setBuildSbomId(Long buildSbomId) {
        this.buildSbomId = buildSbomId;
    }

    public String getScannedVersion() {
        return scannedVersion;
    }

    public void setScannedVersion(String scannedVersion) {
        this.scannedVersion = scannedVersion;
    }

    public String getScannedPurl() {
        return scannedPurl;
    }

    public void setScannedPurl(String scannedPurl) {
        this.scannedPurl = scannedPurl;
    }

    public String getDeclaredLicense() {
        return declaredLicense;
    }

    public void setDeclaredLicense(String declaredLicense) {
        this.declaredLicense = declaredLicense;
    }
}
