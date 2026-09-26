package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.scanning.ScanFindingView;
import com.asmolabs.vectispire.core.services.scanning.ScanQueryService;
import com.asmolabs.vectispire.core.services.scanning.ScanView;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import java.util.List;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Scan history, and the detail of an individual scan.
 *
 * <p><b>The detail shows the scan's findings, not the target's backlog.</b> The two differ: the
 * backlog carries history — an issue seen three scans ago and still open belongs to it — while
 * a scan reports only what it observed that day. Conflating them would suggest a scan "found"
 * an issue it merely saw again.
 */
@Tag(name = "Scans", description = "Security scan lifecycle, pipeline execution and status reporting")
@RestController
@RequestMapping("/api/v1/scans")
@RequiresAccount
public class ScansController {

    private final ScanQueryService scans;
    private final VisibilityService visibility;

    public ScansController(ScanQueryService scans, VisibilityService visibility) {
        this.scans = scans;
        this.visibility = visibility;
    }

    public record ScanSummary(
            Long id,
            String status,
            String branch,
            Instant createdAt,
            Long durationMs,
            int findingsCount,
            int newIssuesCount,
            int resolvedIssuesCount,
            String error,
            String claimedBy,
            int attempts,
            String targetKind,
            Long targetId,
            String targetName) {}

    public record FindingView(
            Long id,
            String type,
            String severity,
            String identifier,
            String packageName,
            String packageVersion,
            String fixVersions,
            String filePath,
            Integer line,
            String description,
            String link) {}

    /**
     * @param findingsTruncated said explicitly, or a scan of a thousand findings would show five
     *     hundred in silence
     * @param projectType and {@code projectVersion} what the scanned tree says about itself, both
     *     null when it carries no manifest this can read. On the detail rather than in the list:
     *     it answers "which build did this" for one scan, and would be a column of blanks in a
     *     history where most rows are container scans
     */
    public record ScanDetail(
            ScanSummary scan,
            String subPath,
            String projectType,
            String projectVersion,
            boolean hasSbom,
            List<FindingView> findings,
            long findingsTotal,
            boolean findingsTruncated) {}

    @Operation(summary = "List scan history", description = "Returns historical security scans with filtering by repository or container target.")
    @ApiResponse(responseCode = "200", description = "Scan history retrieved successfully")
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping
    public List<ScanSummary> list(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Filter by repository ID") @RequestParam(name = "repo_id", required = false) Long repoId,
            @Parameter(description = "Filter by container ID") @RequestParam(name = "container_id", required = false) Long containerId,
            @Parameter(description = "Maximum results to return") @RequestParam(required = false, defaultValue = "50") int limit) {

        ScanQueryService.History history = scans.history(allowed(principal), repoId, containerId, limit);
        return history.scans().stream()
                .map(scan -> summaryOf(scan, history.names()))
                .toList();
    }

    @Operation(summary = "Get scan detail", description = "Returns full details and raw findings observed during a specific scan.")
    @ApiResponse(responseCode = "200", description = "Scan details retrieved successfully")
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping("/{id}")
    public ScanDetail detail(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Scan ID", required = true) @PathVariable long id) {
        ScanQueryService.Detail detail = scans.detail(id, allowed(principal));
        ScanView scan = detail.scan();

        return new ScanDetail(
                summaryOf(scan, detail.names()),
                scan.subPath(),
                scan.projectType(),
                scan.version(),
                // The SBOM is not returned here: it weighs megabytes and the screen shows none
                // of it. It is served whole by `/{id}/sbom` instead, so a caller who wants it
                // asks for it.
                scan.sbom() != null,
                detail.findings().stream().map(ScansController::viewOf).toList(),
                detail.findingsTotal(),
                detail.findingsTruncated());
    }

    /**
     * The SBOM exactly as the cataloguer produced it.
     *
     * <p><b>This route was documented and did not exist.</b> The README announced it twice, the
     * API key scope offered "retrieve SARIF, OpenVEX, SBOM", the detail payload carried a
     * {@code hasSbom} flag and this very class said its export had its own route — four claims,
     * no mapping. The document was already stored on every scan; only the way out was missing.
     *
     * <p>Served verbatim rather than re-serialized: an SBOM is consumed by other tools, and a
     * document that has been through a parser and a writer is no longer byte-for-byte what the
     * cataloguer signed off. 404 when the scan produced none — a scan that failed before the
     * inventory has no SBOM, and an empty document would claim it inventoried nothing.
     */
    @Operation(summary = "Download scan SBOM", description = "Returns the complete Software Bill of Materials (SBOM) produced during this scan.")
    @ApiResponse(
            responseCode = "200",
            // Syft's native JSON, served byte for byte — see decision 0016. This said "CycloneDX /
            // SPDX" and served neither, which is what an integrator builds against before
            // discovering the parse fails. The generated CycloneDX-with-VEX document is a
            // different endpoint: /api/v1/cyclonedx.
            description = "Syft native JSON SBOM document, exactly as the cataloguer produced it")
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping(value = "/{id}/sbom", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> sbom(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Scan ID", required = true) @PathVariable long id) {
        String document = scans.sbom(id, allowed(principal));

        // An attachment: the payload runs to megabytes of JSON, and a browser asked to render it
        // inline freezes on the tab rather than saving the file the caller came for.
        return ResponseEntity.ok()
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment()
                                .filename("vectispire-scan-" + id + ".sbom.json")
                                .build()
                                .toString())
                .contentType(MediaType.APPLICATION_JSON)
                .body(document);
    }

    private Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }

    private static ScanSummary summaryOf(ScanView scan, TargetNaming.Names names) {
        return new ScanSummary(
                scan.id(),
                scan.status(),
                scan.branch(),
                scan.createdAt(),
                scan.durationMs(),
                scan.findingsCount(),
                scan.newIssuesCount(),
                scan.resolvedIssuesCount(),
                scan.error(),
                scan.claimedBy(),
                scan.attempts(),
                scan.repoId() != null ? "repository" : "container",
                scan.repoId() != null ? scan.repoId() : scan.containerId(),
                names.of(scan.repoId(), scan.containerId()));
    }

    private static FindingView viewOf(ScanFindingView finding) {
        return new FindingView(
                finding.id(),
                finding.type(),
                finding.severity(),
                finding.identifier(),
                finding.packageName(),
                finding.packageVersion(),
                finding.fixVersions(),
                finding.filePath(),
                finding.line(),
                finding.description(),
                finding.link());
    }
}
