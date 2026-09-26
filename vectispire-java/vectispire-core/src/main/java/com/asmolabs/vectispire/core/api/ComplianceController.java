package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.core.api.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.ComplianceExportService;
import com.asmolabs.vectispire.core.services.ComplianceService;
import com.asmolabs.vectispire.core.services.access.VisibilityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
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
 * Regulatory compliance matrix and executive posture endpoints (NIS 2, DORA, ISO 27001, PCI-DSS).
 */
@Tag(name = "Compliance", description = "Regulatory conformity frameworks (NIS2, ISO 27001, CRA, SOC2, PCI-DSS)")
@RestController
@RequestMapping("/api/v1/compliance")
@RequiresAccount
public class ComplianceController {

    private final ComplianceService compliance;
    private final ComplianceExportService exports;
    private final VisibilityService visibility;

    public ComplianceController(
            ComplianceService compliance, ComplianceExportService exports, VisibilityService visibility) {
        this.compliance = compliance;
        this.exports = exports;
        this.visibility = visibility;
    }

    @Operation(summary = "Get compliance summary", description = "Returns compliance scores across all regulatory frameworks.")
    @ApiResponse(responseCode = "200", description = "Compliance summary evaluated successfully")
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping("/summary")
    public ComplianceService.ComplianceSummary summary(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Optional target ID filter") @RequestParam(name = "targetId", required = false) String targetId) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        return compliance.getSummary(targetId, allowed);
    }

    @Operation(summary = "Get framework compliance details", description = "Returns detailed conformity evaluation for a specific framework (e.g. NIS2, ISO_27001).")
    @ApiResponse(responseCode = "200", description = "Framework evaluation details")
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping("/frameworks/{framework}")
    public ComplianceEvaluation framework(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Framework identifier, separators and case aside (e.g. NIS2, ISO-27001, EU_CRA)", required = true) @PathVariable String framework) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        ComplianceFramework fw = ComplianceFramework.fromIdentifier(framework);
        return compliance.getEvaluation(fw, allowed);
    }

    @Operation(summary = "Export compliance PDF report", description = "Generates an executive PDF compliance audit report.")
    @ApiResponse(responseCode = "200", description = "Generated PDF report document")
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping(value = "/export.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> exportPdf(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Optional target ID filter") @RequestParam(name = "targetId", required = false) String targetId,
            HttpServletRequest request) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        byte[] pdf = exports.reportPdf(targetId, allowed, RequestActors.of(principal, request, "unknown"));

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment()
                                .filename("vectispire-compliance-report.pdf")
                                .build()
                                .toString())
                .body(pdf);
    }

    @Operation(summary = "Export certified audit evidence bundle", description = "Generates a cryptographically sealed ZIP bundle containing compliance evidence, SHA-256 integrity proofs, and policy audit logs.")
    @ApiResponse(responseCode = "200", description = "Certified evidence bundle ZIP archive")
    // **The stricter of the two doors this data has.** The archive contains the complete audit
    // log, which `/api/v1/audit-log` has always reserved to a security lead — so a reader could
    // obtain by export what they were refused by route. It is also a compliance officer's
    // artifact by nature: signed, dated, and meant for somebody outside the team.
    @RequiresGovernanceRead
    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping(value = "/evidence-bundle.zip", produces = "application/zip")
    public ResponseEntity<byte[]> exportEvidenceBundle(
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) throws java.io.IOException {

        byte[] zip = exports.evidenceBundle(
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()),
                RequestActors.of(principal, request, "unknown"));
        String filename = "vectispire-audit-evidence-bundle.zip";

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/zip"))
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment()
                                .filename(filename)
                                .build()
                                .toString())
                .body(zip);
    }
}
