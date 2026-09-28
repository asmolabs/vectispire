package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportEntity;
import java.time.Instant;
import java.util.UUID;

/**
 * An accepted test-report import, under the entity's property names: its totals, counted from the
 * test cases. The suites are {@link TestSuiteResultView}s, read with {@link LatestTestReport}.
 *
 * @param format {@code junit} or {@code junit-zip}, as the request's media type declared it
 * @param documentsCount how many JUnit documents it held — one, or the zip's {@code .xml} entries
 * @param testsCount includes the failed, errored and skipped ones
 * @param commit and {@code branch}: what the pipeline stated, verified against nothing
 */
public record TestReportImportView(
        Long id,
        Long sourceId,
        String sourceSlug,
        Long repoId,
        String format,
        int documentsCount,
        int suitesCount,
        int testsCount,
        int failuresCount,
        int errorsCount,
        int skippedCount,
        String commit,
        String branch,
        String documentSha256,
        Instant importedAt,
        String importedBy,
        UUID apiKeyId) {

    static TestReportImportView of(TestReportImportEntity row) {
        return new TestReportImportView(row.getId(), row.getSourceId(), row.getSourceSlug(), row.getRepoId(),
                row.getFormat(), row.getDocumentsCount(), row.getSuitesCount(), row.getTestsCount(), row.getFailuresCount(),
                row.getErrorsCount(), row.getSkippedCount(), row.getCommit(), row.getBranch(), row.getDocumentSha256(),
                row.getImportedAt(), row.getImportedBy(), row.getApiKeyId());
    }
}
