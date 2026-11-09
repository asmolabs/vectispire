package com.asmolabs.vectispire.core.exports.web;

import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.cyclonedx.CycloneDxDocument;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.exports.CycloneDxGeneratorService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import io.swagger.v3.oas.annotations.Operation;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * REST controller exposing CycloneDX 1.5/1.6 SBOM with BOM-linked VEX advisories.
 */
@RestController
@RequestMapping("/api/v1/cyclonedx")
@RequiresAccount
public class CycloneDxController {

    private final CycloneDxGeneratorService cycloneDxService;
    private final SolutionQueryService projects;
    private final VisibilityService visibility;

    public CycloneDxController(
            CycloneDxGeneratorService cycloneDxService, SolutionQueryService projects, VisibilityService visibility) {
        this.cycloneDxService = cycloneDxService;
        this.projects = projects;
        this.visibility = visibility;
    }

    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping(value = "/scans/{scanId}/cyclonedx-vex.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CycloneDxDocument> getScanCycloneDx(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable("scanId") Long scanId) {
        // Refused by the service, beside the read, for a scan the caller may not see.
        CycloneDxDocument doc = cycloneDxService.generateForScan(scanId, allowanceOf(principal).visibility())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found."));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-" + scanId + "-cyclonedx-vex.json\"")
                .body(doc);
    }

    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping(value = "/aggregate.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CycloneDxDocument> getAggregateCycloneDx(
            @AuthenticationPrincipal VectispirePrincipal principal) {
        CycloneDxDocument doc = cycloneDxService.generateAggregate(allowanceOf(principal).visibility());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"vectispire-aggregate-cyclonedx-vex.json\"")
                .body(doc);
    }

    /**
     * A project's consolidated SBOM with its VEX. The refusal is {@code targets}' guard — this module's
     * services do not use {@code access} — and the service takes the proof it returns, never the id.
     */
    @Operation(summary = "Project CycloneDX document", description = "The project's consolidated SBOM — the "
            + "components of the newest completed scan of each repository and image the caller may see, merged — as "
            + "CycloneDX 1.5, with the project's CVE issues as BOM-linked VEX. Each component names the targets carrying "
            + "it (property vectispire:target); compositions says complete only when every target of the project was "
            + "seen and its inventory read. Not signed, like the other exports. 404 \"Project not found.\" for a project "
            + "that does not exist and one the caller sees nothing of.")
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping(value = "/projects/{projectId}/cyclonedx-vex.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CycloneDxDocument> getProjectCycloneDx(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable("projectId") long projectId) {
        VisibleScope project = projects.visibleProject(projectId, allowanceOf(principal));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"project-" + projectId + "-cyclonedx-vex.json\"")
                .body(cycloneDxService.generateForProject(project));
    }

    /** The caller's visibility, with the projects it holds as such — which a project's scope reads. */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }

}
