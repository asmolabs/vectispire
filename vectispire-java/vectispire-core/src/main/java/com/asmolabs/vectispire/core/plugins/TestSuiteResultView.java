package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultEntity;

/** One suite of an accepted test report, under the entity's property names. */
public record TestSuiteResultView(
        Long id, Long importId, String name, int testsCount, int failuresCount, int errorsCount, int skippedCount) {

    static TestSuiteResultView of(TestSuiteResultEntity row) {
        return new TestSuiteResultView(row.getId(), row.getImportId(), row.getName(), row.getTestsCount(),
                row.getFailuresCount(), row.getErrorsCount(), row.getSkippedCount());
    }
}
