package com.asmolabs.vectispire.core.plugins.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One package of an accepted coverage report — its path and its counts — written only when the
 * report's packages added up to its totals. Named by its import's id and no foreign key (a common
 * migration): the purge removes the packages before their imports.
 */
@Entity
@Table(name = "t_coverage_package")
public class CoveragePackageEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "import_id", nullable = false)
    private Long importId;

    /** Segments joined by {@code /}, the top level empty — {@code CoveragePackages.path}. */
    @Column(name = "path", length = 1000, nullable = false)
    private String path;

    @Column(name = "lines_covered", nullable = false)
    private long linesCovered;

    @Column(name = "lines_total", nullable = false)
    private long linesTotal;

    @Column(name = "branches_covered")
    private Long branchesCovered;

    @Column(name = "branches_total")
    private Long branchesTotal;

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

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public long getLinesCovered() {
        return linesCovered;
    }

    public void setLinesCovered(long linesCovered) {
        this.linesCovered = linesCovered;
    }

    public long getLinesTotal() {
        return linesTotal;
    }

    public void setLinesTotal(long linesTotal) {
        this.linesTotal = linesTotal;
    }

    public Long getBranchesCovered() {
        return branchesCovered;
    }

    public void setBranchesCovered(Long branchesCovered) {
        this.branchesCovered = branchesCovered;
    }

    public Long getBranchesTotal() {
        return branchesTotal;
    }

    public void setBranchesTotal(Long branchesTotal) {
        this.branchesTotal = branchesTotal;
    }
}
