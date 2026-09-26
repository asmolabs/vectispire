package com.asmolabs.vectispire.core.services.compliance;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.audit.RequestActor;
import com.asmolabs.vectispire.core.services.settings.BrandingProperties;
import java.io.IOException;
import java.time.Clock;
import org.springframework.stereotype.Service;

/**
 * The two compliance documents that leave the building, and the audit entry each one leaves
 * behind.
 *
 * <p><b>Its own bean rather than a method on {@link ComplianceService} or {@link
 * EvidenceVaultService}</b>, because both reads are {@code @Transactional(readOnly = true)} and the
 * audit entry has to be written outside them: it opens its own transaction, and inside a caller's
 * it waits on that caller's connection on SQLite. A method beside the read would call it through
 * {@code this}, bypass the proxy and run it with no transaction at all. Calling across beans keeps
 * both boundaries where they were when the route did this itself.
 */
@Service
public class ComplianceExportService {

    private final ComplianceService compliance;
    private final EvidenceVaultService evidenceVault;
    private final AuditLogService audit;
    private final BrandingProperties branding;
    private final Clock clock;

    public ComplianceExportService(
            ComplianceService compliance,
            EvidenceVaultService evidenceVault,
            AuditLogService audit,
            BrandingProperties branding,
            Clock clock) {
        this.compliance = compliance;
        this.evidenceVault = evidenceVault;
        this.audit = audit;
        this.branding = branding;
        this.clock = clock;
    }

    /** The executive PDF, within the caller's allowance; audited once the figures are read. */
    public byte[] reportPdf(String targetId, Visibility allowed, RequestActor actor) {
        ComplianceService.ComplianceSummary summary = compliance.getSummary(targetId, allowed);

        audit.record(actor.entry(
                AuditOperation.REPORT_EXPORTED,
                "compliance",
                "Regulatory Compliance PDF report exported" + (targetId != null ? " for " + targetId : "")));

        return ComplianceReportPdf.render(
                new ComplianceReportPdf.Subject(
                        clock.instant(),
                        summary.totalMonitoredTargets(),
                        summary.passingGateTargets(),
                        summary.mttr().overallMttrDays(),
                        summary.overdueCount(),
                        branding.name()),
                summary.evaluations());
    }

    /**
     * The certified evidence bundle, within the caller's allowance.
     *
     * <p>Audited <b>before</b> the archive is built, as the route always did — which puts the
     * export's own entry inside the audit log the bundle carries.
     */
    public byte[] evidenceBundle(Visibility allowed, RequestActor actor) throws IOException {
        audit.record(actor.entry(
                AuditOperation.REPORT_EXPORTED, "evidence_vault", "Certified Audit Evidence Bundle exported"));

        return evidenceVault.generateEvidenceBundle(actor.username(), allowed);
    }
}
