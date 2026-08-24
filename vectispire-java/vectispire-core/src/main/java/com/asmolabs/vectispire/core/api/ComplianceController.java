package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.ComplianceReportPdf;
import com.asmolabs.vectispire.core.services.ComplianceService;
import com.asmolabs.vectispire.core.services.EvidenceVaultService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Regulatory compliance matrix and executive posture endpoints (NIS 2, DORA, ISO 27001, PCI-DSS).
 */
@RestController
@RequestMapping("/api/v1/compliance")
@RequiresAccount
public class ComplianceController {

    private final ComplianceService compliance;
    private final VisibilityService visibility;
    private final AuditLogService audit;
    private final EvidenceVaultService evidenceVault;
    private final Clock clock;

    public ComplianceController(
            ComplianceService compliance,
            VisibilityService visibility,
            AuditLogService audit,
            EvidenceVaultService evidenceVault,
            Clock clock) {
        this.compliance = compliance;
        this.visibility = visibility;
        this.audit = audit;
        this.evidenceVault = evidenceVault;
        this.clock = clock;
    }

    @GetMapping("/summary")
    public ComplianceService.ComplianceSummary summary(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @org.springframework.web.bind.annotation.RequestParam(name = "targetId", required = false) String targetId) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        return compliance.getSummary(targetId, allowed);
    }

    @GetMapping("/frameworks/{framework}")
    public ComplianceEvaluation framework(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable String framework) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        ComplianceFramework fw = ComplianceFramework.valueOf(framework.toUpperCase().replace('-', '_'));
        return compliance.getEvaluation(fw, allowed);
    }

    @GetMapping(value = "/export.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> exportPdf(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @org.springframework.web.bind.annotation.RequestParam(name = "targetId", required = false) String targetId,
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
                        summary.overdueCount()),
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

        byte[] zip = evidenceVault.generateEvidenceBundle(username);
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
