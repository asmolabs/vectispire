package com.asmolabs.vectispire.core.plugins.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One suite of an accepted test report, counted from its test cases. Named by its import's id and no
 * foreign key (a common migration): the purge removes the suites before their imports.
 */
@Entity
@Table(name = "t_test_suite_result")
public class TestSuiteResultEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "import_id", nullable = false)
    private Long importId;

    @Column(name = "name", length = 500, nullable = false)
    private String name;

    @Column(name = "tests_count", nullable = false)
    private int testsCount;

    @Column(name = "failures_count", nullable = false)
    private int failuresCount;

    @Column(name = "errors_count", nullable = false)
    private int errorsCount;

    @Column(name = "skipped_count", nullable = false)
    private int skippedCount;

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

    public int getTestsCount() {
        return testsCount;
    }

    public void setTestsCount(int testsCount) {
        this.testsCount = testsCount;
    }

    public int getFailuresCount() {
        return failuresCount;
    }

    public void setFailuresCount(int failuresCount) {
        this.failuresCount = failuresCount;
    }

    public int getErrorsCount() {
        return errorsCount;
    }

    public void setErrorsCount(int errorsCount) {
        this.errorsCount = errorsCount;
    }

    public int getSkippedCount() {
        return skippedCount;
    }

    public void setSkippedCount(int skippedCount) {
        this.skippedCount = skippedCount;
    }
}
