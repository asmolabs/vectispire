package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.reports.CoverageFormat;
import com.asmolabs.vectispire.common.domain.reports.CoverageReport;
import com.asmolabs.vectispire.common.domain.reports.TestReport;
import com.asmolabs.vectispire.common.domain.reports.TestReportFormat;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.SarifSourceEntity;
import com.asmolabs.vectispire.core.plugins.persistence.SarifSourceRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportEntity;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultEntity;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultRepository;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.unit.DataSize;

/**
 * Recording a declared internal source's coverage and test reports for a repository (decision 0032
 * §7, amending 0017 §7).
 *
 * <h2>Who may, and what is checked, in 0017's order</h2>
 *
 * <ol>
 *   <li><b>An integration key, never a session</b> (403) — the route accepts {@code report_import}
 *       keys, and a key without the scope is refused before the route (403).</li>
 *   <li><b>A key declared as a source, and enabled</b> (403, audited {@code REPORT_IMPORT_REFUSED}
 *       and signalled {@code VECTI-SEC-027}).</li>
 *   <li><b>The kind among the source's</b>: a source declared for SARIF alone does not deposit
 *       coverage (403, audited and signalled). A key holding {@code report_import} whose source was
 *       declared without the kind is a pipeline sending what nobody declared.</li>
 *   <li><b>A repository the key sees, inside the source's scope</b> — 404 in the words of a
 *       repository that does not exist; outside the scope is audited and signalled too.</li>
 *   <li><b>A document within the ceiling</b> (413), in its declared format, that reads under the
 *       readers' guards and counts something (400).</li>
 * </ol>
 *
 * <h2>What is kept</h2>
 *
 * <p>The figures, never the document: a coverage report's line and branch counts, a test report's
 * totals and its suites. The document's SHA-256, the source and the key are kept with them — the
 * figure is the pipeline's word, and this is what binds the word to a key and to the bytes it sent. The
 * commit and branch a pipeline states are kept as its word too, and verified against nothing. The
 * import is a row, and an audit entry written after the commit.
 *
 * <p>Nothing here opens or resolves an issue: a coverage figure is not a finding. That is also why
 * these kinds take {@code report_import} and not {@code sarif_import}.
 */
@Service
public class ReportImportService {

    /** How many imports a repository's history routes answer. */
    static final int HISTORY = 50;

    /** An abbreviated or a full SHA-1 or SHA-256 commit name. */
    private static final Pattern COMMIT = Pattern.compile("[0-9a-f]{7,64}");

    static final int MAX_BRANCH = 255;

    private final SarifSourceRepository sources;
    private final CoverageImportRepository coverage;
    private final TestReportImportRepository testReports;
    private final TestSuiteResultRepository suites;
    private final TargetCatalog targets;
    private final AuditLogService audit;
    private final TransactionTemplate transactions;
    private final ReportedRepositories reported;
    private final Clock clock;
    private final long maxCoverageBytes;
    private final long maxTestReportBytes;

    public ReportImportService(
            SarifSourceRepository sources,
            CoverageImportRepository coverage,
            TestReportImportRepository testReports,
            TestSuiteResultRepository suites,
            TargetCatalog targets,
            AuditLogService audit,
            TransactionTemplate transactions,
            ReportedRepositories reported,
            Clock clock,
            @Value("${vectispire.http.max-body.coverage-import:16MB}") DataSize maxCoverageBytes,
            @Value("${vectispire.http.max-body.test-report-import:32MB}") DataSize maxTestReportBytes) {
        this.sources = sources;
        this.coverage = coverage;
        this.testReports = testReports;
        this.suites = suites;
        this.targets = targets;
        this.audit = audit;
        this.transactions = transactions;
        this.reported = reported;
        this.clock = clock;
        this.maxCoverageBytes = maxCoverageBytes.toBytes();
        this.maxTestReportBytes = maxTestReportBytes.toBytes();
    }

    /**
     * Who is uploading, as the route resolved it from an integration key.
     *
     * @param allowed the key's account's visibility intersected with the key's own restriction
     */
    public record Uploader(UUID keyId, String keyName, Visibility allowed, RequestActor actor) {}

    /**
     * What the pipeline says the report measured — its word, bounded and kept, never checked.
     *
     * @param commit the commit's name in hexadecimal, 7 to 64 digits, or {@code null}
     * @param branch the branch, or {@code null}
     */
    public record Stated(String commit, String branch) {}

    /**
     * @param format {@code jacoco}, {@code cobertura} or {@code lcov}, as the pipeline declares it
     * @param uploader empty for a caller that is not an integration key — a session — which is refused
     */
    public CoverageImportView importCoverage(
            long repositoryId, String format, byte[] document, Stated stated, Optional<Uploader> uploader) {
        Uploader caller = requireKey(uploader);
        SarifSourceEntity source = admit(caller, repositoryId, SourceKind.COVERAGE);
        requireWithin(document, maxCoverageBytes, "coverage report");
        Stated said = bounded(stated);
        CoverageReport report = CoverageReport.read(CoverageFormat.parse(format), document, maxCoverageBytes);

        CoverageImportEntity row = new CoverageImportEntity();
        row.setSourceId(source.getId());
        row.setSourceSlug(source.getSlug());
        row.setRepoId(repositoryId);
        row.setFormat(report.format().wireName());
        row.setToolVersion(report.toolVersion().orElse(null));
        row.setLinesCovered(report.lines().covered());
        row.setLinesTotal(report.lines().total());
        row.setBranchesCovered(report.branches().map(CoverageReport.Counts::covered).orElse(null));
        row.setBranchesTotal(report.branches().map(CoverageReport.Counts::total).orElse(null));
        row.setCommit(said.commit());
        row.setBranch(said.branch());
        row.setDocumentSha256(Digests.sha256Hex(document));
        row.setImportedAt(clock.instant());
        row.setImportedBy(importedBy(caller));
        row.setApiKeyId(caller.keyId());
        CoverageImportEntity saved = transactions.execute(status -> {
            CoverageImportEntity imported = coverage.save(row);
            reported.announce(repositoryId);
            return imported;
        });

        audit.record(caller.actor().entry(AuditOperation.COVERAGE_IMPORTED, String.valueOf(repositoryId),
                "Coverage from source \"" + source.getSlug() + "\" (" + saved.getFormat() + ") recorded for repository "
                        + repositoryId + ": lines " + saved.getLinesCovered() + "/" + saved.getLinesTotal()
                        + (saved.getBranchesTotal() == null ? ""
                                : ", branches " + saved.getBranchesCovered() + "/" + saved.getBranchesTotal())
                        + stated(said) + ", sha256 " + saved.getDocumentSha256().substring(0, 12) + "."));
        return CoverageImportView.of(saved);
    }

    /**
     * @param mediaType the request's {@code Content-Type}: one JUnit document, or a zip of them
     * @param uploader empty for a caller that is not an integration key — a session — which is refused
     */
    public TestReportImportView importTestReport(
            long repositoryId, String mediaType, byte[] document, Stated stated, Optional<Uploader> uploader) {
        Uploader caller = requireKey(uploader);
        SarifSourceEntity source = admit(caller, repositoryId, SourceKind.TEST_REPORT);
        requireWithin(document, maxTestReportBytes, "test report");
        Stated said = bounded(stated);
        TestReport report = TestReport.read(TestReportFormat.ofMediaType(mediaType), document, maxTestReportBytes);

        String sha256 = Digests.sha256Hex(document);
        Instant now = clock.instant();
        TestReportImportEntity saved = transactions.execute(status -> {
            TestReportImportEntity row = new TestReportImportEntity();
            row.setSourceId(source.getId());
            row.setSourceSlug(source.getSlug());
            row.setRepoId(repositoryId);
            row.setFormat(report.format().wireName());
            row.setDocumentsCount(report.documents());
            row.setSuitesCount(report.suites().size());
            row.setTestsCount(report.tests());
            row.setFailuresCount(report.failures());
            row.setErrorsCount(report.errors());
            row.setSkippedCount(report.skipped());
            row.setCommit(said.commit());
            row.setBranch(said.branch());
            row.setDocumentSha256(sha256);
            row.setImportedAt(now);
            row.setImportedBy(importedBy(caller));
            row.setApiKeyId(caller.keyId());
            TestReportImportEntity imported = testReports.save(row);
            suites.saveAll(report.suites().stream().map(suite -> {
                TestSuiteResultEntity entity = new TestSuiteResultEntity();
                entity.setImportId(imported.getId());
                entity.setName(suite.name());
                entity.setTestsCount(suite.tests());
                entity.setFailuresCount(suite.failures());
                entity.setErrorsCount(suite.errors());
                entity.setSkippedCount(suite.skipped());
                return entity;
            }).toList());
            reported.announce(repositoryId);
            return imported;
        });

        audit.record(caller.actor().entry(AuditOperation.TEST_REPORT_IMPORTED, String.valueOf(repositoryId),
                "Test report from source \"" + source.getSlug() + "\" (" + saved.getFormat() + ", "
                        + saved.getDocumentsCount() + " document(s)) recorded for repository " + repositoryId + ": "
                        + saved.getSuitesCount() + " suite(s), " + saved.getTestsCount() + " test(s), "
                        + saved.getFailuresCount() + " failed, " + saved.getErrorsCount() + " in error, "
                        + saved.getSkippedCount() + " skipped" + stated(said) + ", sha256 " + sha256.substring(0, 12) + "."));
        return TestReportImportView.of(saved);
    }

    /** A repository's latest coverage imports, within the caller's visibility — 404 for one it cannot see. */
    public List<CoverageImportView> coverageHistory(long repositoryId, Visibility allowed) {
        requireVisible(repositoryId, allowed);
        return coverage.findByRepoIdOrderByImportedAtDescIdDesc(repositoryId, PageRequest.of(0, HISTORY)).stream()
                .map(CoverageImportView::of)
                .toList();
    }

    /** A repository's latest test-report imports, within the caller's visibility — 404 for one it cannot see. */
    public List<TestReportImportView> testReportHistory(long repositoryId, Visibility allowed) {
        requireVisible(repositoryId, allowed);
        return testReports.findByRepoIdOrderByImportedAtDescIdDesc(repositoryId, PageRequest.of(0, HISTORY)).stream()
                .map(TestReportImportView::of)
                .toList();
    }

    private static Uploader requireKey(Optional<Uploader> uploader) {
        return uploader.orElseThrow(() -> new ReportImportRefusedException("Coverage and test reports are imported "
                + "with a declared source's integration key; a session is not a source."));
    }

    /**
     * Steps 2 to 4: the source the key names, enabled; the kind among its kinds; the repository
     * visible to the key and inside the source's scope. Each refusal of what the caller claims is
     * audited, and through the entry signalled; a hidden repository is not — it is the key's own
     * visibility, not a claim.
     */
    private SarifSourceEntity admit(Uploader caller, long repositoryId, SourceKind kind) {
        String resource = String.valueOf(repositoryId);
        SarifSourceEntity source = sources.findByApiKeyId(caller.keyId())
                .filter(SarifSourceEntity::getEnabled)
                .orElseThrow(() -> refused(caller, resource, "the key \"" + caller.keyName()
                        + "\" is not declared as an enabled source", "This key is not declared as an enabled source."));
        if (!SourceKind.fromStored(source.getKinds()).contains(kind)) {
            throw refused(caller, resource, "source \"" + source.getSlug() + "\" is not declared to deliver "
                    + kind.wireName(), "Source \"" + source.getSlug() + "\" is not declared to deliver " + kind.wireName()
                    + "; the platform governor declares what a source may deliver.");
        }
        RepositoryView repository = requireVisible(repositoryId, caller.allowed());
        if (!inScope(source, repository)) {
            refused(caller, resource, "source \"" + source.getSlug() + "\" is not declared for repository "
                    + repositoryId, null);
            throw absent(repositoryId);
        }
        return source;
    }

    private RepositoryView requireVisible(long repositoryId, Visibility allowed) {
        return targets.repository(repositoryId)
                .filter(found -> allowed.permits(new ScanTarget.Repository(repositoryId)))
                .orElseThrow(() -> absent(repositoryId));
    }

    private static NotFoundException absent(long repositoryId) {
        return new NotFoundException("No repository " + repositoryId + ".");
    }

    private static boolean inScope(SarifSourceEntity source, RepositoryView repository) {
        if (source.getRepositoryId() != null) {
            return source.getRepositoryId().equals(repository.id());
        }
        return source.getProjectId() != null && source.getProjectId().equals(repository.projectId());
    }

    private static void requireWithin(byte[] document, long maxBytes, String what) {
        if (document != null && document.length > maxBytes) {
            throw new ReportTooLargeException("The " + what + " is larger than the " + maxBytes + " bytes accepted.");
        }
    }

    /** The pipeline's word, bounded to its columns — refused in words rather than cut. */
    private static Stated bounded(Stated stated) {
        String commit = stated == null || stated.commit() == null || stated.commit().isBlank()
                ? null
                : stated.commit().strip().toLowerCase(Locale.ROOT);
        if (commit != null && !COMMIT.matcher(commit).matches()) {
            throw new InvalidInputException("A commit is named by 7 to 64 hexadecimal digits.");
        }
        String branch = stated == null || stated.branch() == null || stated.branch().isBlank()
                ? null
                : stated.branch().strip();
        if (branch != null && (branch.length() > MAX_BRANCH || branch.chars().anyMatch(Character::isISOControl))) {
            throw new InvalidInputException("A branch name is at most " + MAX_BRANCH + " characters, with no control "
                    + "character.");
        }
        return new Stated(commit, branch);
    }

    private static String stated(Stated said) {
        return (said.commit() == null ? "" : ", commit " + said.commit())
                + (said.branch() == null ? "" : ", branch " + said.branch());
    }

    private static String importedBy(Uploader caller) {
        return caller.actor() == null || caller.actor().username() == null
                ? "key:" + caller.keyName()
                : caller.actor().username();
    }

    /**
     * Records the refusal — the entry, and through it the SIEM event — and returns the exception to
     * throw, or {@code null} when the caller answers something else (a 404 hiding the repository).
     */
    private ReportImportRefusedException refused(Uploader caller, String resource, String why, String answer) {
        audit.record(caller.actor().entry(AuditOperation.REPORT_IMPORT_REFUSED, resource,
                "Report import refused: " + why + "."));
        return answer == null ? null : new ReportImportRefusedException(answer);
    }
}
