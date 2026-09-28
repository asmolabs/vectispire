package com.asmolabs.vectispire.core.plugins.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresWriteAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.plugins.CoverageImportView;
import com.asmolabs.vectispire.core.plugins.ReportImportService;
import com.asmolabs.vectispire.core.plugins.TestReportImportView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * A declared internal source's coverage and test reports, recorded for one repository (decision 0032
 * §7).
 *
 * <p><b>Only with a declared source's integration key</b> — {@code @AcceptsApiKey(REPORT_IMPORT)} lets
 * such a key reach the routes, and the service refuses anything else, a session included, in 0017's
 * order. The account the key acts for must be able to cause effects ({@code @RequiresWriteAccount}),
 * as for SARIF: a recorded figure is what a checklist will read. The bodies are capped by the routes'
 * filter ({@code vectispire.http.max-body.coverage-import}, {@code .test-report-import}) before they
 * are read. The format is the pipeline's to declare and the service's to parse: the query parameter
 * for coverage, the media type for a test report.
 */
@Tag(name = "Report import", description = "Coverage and test reports from declared internal sources")
@RestController
@RequestMapping("/api/v1/repositories/{repositoryId}")
public class ReportImportsController {

    private final ReportImportService imports;
    private final VisibilityService visibility;

    public ReportImportsController(ReportImportService imports, VisibilityService visibility) {
        this.imports = imports;
        this.visibility = visibility;
    }

    @Operation(summary = "Import coverage report", description = "A declared internal source's integration key only "
            + "(scope report_import), for a source declared to deliver coverage. format is jacoco, cobertura or lcov — "
            + "declared, never guessed; commit and branch are kept as stated. 403 for a session, an undeclared key or "
            + "a source not declared for coverage; 404 for a repository outside the key's visibility or the source's "
            + "scope; 413 past the size ceiling; 400 for a body that does not read as the format or counts no line.")
    @PostMapping(value = "/coverage-imports",
            consumes = {"application/xml", "text/xml", "text/plain", "application/octet-stream"})
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresWriteAccount
    @AcceptsApiKey(ApiKeyScope.REPORT_IMPORT)
    public CoverageImportView importCoverage(
            @PathVariable long repositoryId,
            @RequestParam(required = false) String format,
            @RequestParam(required = false) String commit,
            @RequestParam(required = false) String branch,
            @RequestBody byte[] document,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return imports.importCoverage(repositoryId, format, document, new ReportImportService.Stated(commit, branch),
                uploader(principal, request));
    }

    @Operation(summary = "Import test report", description = "A declared internal source's integration key only "
            + "(scope report_import), for a source declared to deliver test_report. One JUnit XML document "
            + "(application/xml) or a zip of them (application/zip); commit and branch are kept as stated. 403 for a "
            + "session, an undeclared key or a source not declared for test reports; 404 for a repository outside the "
            + "key's visibility or the source's scope; 413 past the size ceiling; 400 for a body that is not JUnit, "
            + "a zip past its guards, or a report with no test case.")
    @PostMapping(value = "/test-report-imports", consumes = {"application/xml", "text/xml", "application/zip"})
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresWriteAccount
    @AcceptsApiKey(ApiKeyScope.REPORT_IMPORT)
    public TestReportImportView importTestReport(
            @PathVariable long repositoryId,
            @RequestParam(required = false) String commit,
            @RequestParam(required = false) String branch,
            @RequestBody byte[] document,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {
        return imports.importTestReport(repositoryId, request.getContentType(), document,
                new ReportImportService.Stated(commit, branch), uploader(principal, request));
    }

    @Operation(summary = "List repository's coverage imports", description = "The latest fifty. 404 for a repository "
            + "the caller cannot see.")
    @GetMapping("/coverage-imports")
    @RequiresAccount
    @AcceptsApiKey(ApiKeyScope.READ)
    public List<CoverageImportView> coverageHistory(
            @PathVariable long repositoryId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return imports.coverageHistory(repositoryId, allowed(principal));
    }

    @Operation(summary = "List repository's test-report imports", description = "The latest fifty, without their "
            + "suites. 404 for a repository the caller cannot see.")
    @GetMapping("/test-report-imports")
    @RequiresAccount
    @AcceptsApiKey(ApiKeyScope.READ)
    public List<TestReportImportView> testReportHistory(
            @PathVariable long repositoryId, @AuthenticationPrincipal VectispirePrincipal principal) {
        return imports.testReportHistory(repositoryId, allowed(principal));
    }

    private Optional<ReportImportService.Uploader> uploader(VectispirePrincipal principal, HttpServletRequest request) {
        return principal.integration().map(integration -> new ReportImportService.Uploader(
                integration.keyId(), integration.keyName(), allowed(principal), RequestActors.of(principal, request)));
    }

    private Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }
}
