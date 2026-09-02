package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.ComplianceReportPdf;
import com.asmolabs.vectispire.core.services.ComplianceService;
import com.asmolabs.vectispire.core.services.EvidenceVaultService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
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
    private final VisibilityService visibility;
    private final AuditLogService audit;
    private final EvidenceVaultService evidenceVault;
    private final com.asmolabs.vectispire.core.services.BrandingProperties branding;
    private final Clock clock;

    public ComplianceController(
            ComplianceService compliance,
            VisibilityService visibility,
            AuditLogService audit,
            EvidenceVaultService evidenceVault,
            com.asmolabs.vectispire.core.services.BrandingProperties branding,
            Clock clock) {
        this.compliance = compliance;
        this.visibility = visibility;
        this.audit = audit;
        this.evidenceVault = evidenceVault;
        this.branding = branding;
        this.clock = clock;
    }

    @Operation(summary = "Get compliance summary", description = "Returns compliance scores across all regulatory frameworks.")
    @ApiResponse(responseCode = "200", description = "Compliance summary evaluated successfully")
    @GetMapping("/summary")
    public ComplianceService.ComplianceSummary summary(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Optional target ID filter") @RequestParam(name = "targetId", required = false) String targetId) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        return compliance.getSummary(targetId, allowed);
    }

    @Operation(summary = "Get framework compliance details", description = "Returns detailed conformity evaluation for a specific framework (e.g. NIS2, ISO_27001).")
    @ApiResponse(responseCode = "200", description = "Framework evaluation details")
    @GetMapping("/frameworks/{framework}")
    public ComplianceEvaluation framework(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Framework identifier (e.g. NIS2, ISO-27001, CRA)", required = true) @PathVariable String framework) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        ComplianceFramework fw = ComplianceFramework.valueOf(framework.toUpperCase().replace('-', '_'));
        return compliance.getEvaluation(fw, allowed);
    }

    @Operation(summary = "Export compliance PDF report", description = "Generates an executive PDF compliance audit report.")
    @ApiResponse(responseCode = "200", description = "Generated PDF report document")
    @GetMapping(value = "/export.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> exportPdf(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Optional target ID filter") @RequestParam(name = "targetId", required = false) String targetId,
            HttpServletRequest request) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        ComplianceService.ComplianceSummary summary = compliance.getSummary(targetId, allowed);

        audit.record(new AuditLogService.Record(
                AuditOperation.AI_REVIEW_REQUESTED,
                "compliance",
                "Regulatory Compliance PDF report exported" + (targetId != null ? " for " + targetId : ""),
                principal.user().map(u -> u.getUsername()).orElse("unknown"),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        byte[] pdf = ComplianceReportPdf.render(
                new ComplianceReportPdf.Subject(
                        clock.instant(),
                        summary.totalMonitoredTargets(),
                        summary.passingGateTargets(),
                        summary.mttr().overallMttrDays(),
                        summary.overdueCount(),
                        branding.name()),
                summary.evaluations());

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
    @GetMapping(value = "/evidence-bundle.zip", produces = "application/zip")
    public ResponseEntity<byte[]> exportEvidenceBundle(
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) throws java.io.IOException {

        String username = principal.user().map(u -> u.getUsername()).orElse("unknown");
        audit.record(new AuditLogService.Record(
                AuditOperation.AI_REVIEW_REQUESTED,
                "evidence_vault",
                "Certified Audit Evidence Bundle exported",
                username,
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        byte[] zip = evidenceVault.generateEvidenceBundle(
                username, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
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
