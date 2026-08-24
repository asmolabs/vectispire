package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.zanshin.common.domain.compliance.ComplianceFramework;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.ComplianceReportPdf;
import com.asmolabs.zanshin.core.services.ComplianceService;
import com.asmolabs.zanshin.core.services.EvidenceVaultService;
import com.asmolabs.zanshin.core.services.VisibilityService;
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
    public ComplianceService.ComplianceSummary summary(@AuthenticationPrincipal ZanshinPrincipal principal) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        return compliance.getSummary(allowed);
    }

    @GetMapping("/frameworks/{framework}")
    public ComplianceEvaluation framework(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            @PathVariable String framework) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        ComplianceFramework fw = ComplianceFramework.valueOf(framework.toUpperCase().replace('-', '_'));
        return compliance.getEvaluation(fw, allowed);
    }

    @GetMapping(value = "/export.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> exportPdf(
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        ComplianceService.ComplianceSummary summary = compliance.getSummary(allowed);

        audit.record(new AuditLogService.Record(
                AuditOperation.AI_REVIEW_REQUESTED,
                "compliance",
                "Regulatory Compliance PDF report exported",
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
                                .filename("zanshin-compliance-report.pdf")
                                .build()
                                .toString())
                .body(pdf);
    }

    @GetMapping(value = "/evidence-bundle.zip", produces = "application/zip")
    public ResponseEntity<byte[]> exportEvidenceBundle(
            @AuthenticationPrincipal ZanshinPrincipal principal,
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
        String filename = "zanshin-audit-evidence-bundle.zip";

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
