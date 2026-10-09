package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.aireview.AiReviewStatus;
import com.asmolabs.vectispire.common.domain.aireview.OwaspReview;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.compliance.internal.OwaspReportLinks;
import com.asmolabs.vectispire.core.compliance.internal.OwaspReportPdf;
import com.asmolabs.vectispire.core.compliance.internal.OwaspReviewService;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanView;
import com.asmolabs.vectispire.core.settings.BrandingProperties;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Clock;
import org.springframework.stereotype.Service;

/**
 * One repository's OWASP report, as the routes serve it: read, requested, rendered.
 *
 * <p>{@link OwaspReviewService} writes the report; this class decides who may reach it and what
 * surrounds it — the visibility refusal, the audit entry for a run, the cover page of the PDF.
 * Every entry point takes the caller's visibility, so a repository they were not given reads as
 * one that does not exist, on all three — and the figures and links beside a report are counted with
 * the same visibility, so they never describe an issue the backlog would hide ({@link OwaspReportLinks}).
 */
@Service
public class OwaspReportService {

    private static final String NO_REPORT = "No OWASP report has been produced for this target.";

    private final OwaspReviewService reviews;
    private final OwaspReportLinks links;
    private final TargetCatalog targets;
    private final ScanCatalog scans;
    private final IssueCatalog issues;
    private final AuditLogService audit;
    private final BrandingProperties branding;
    private final Clock clock;

    public OwaspReportService(
            OwaspReviewService reviews,
            OwaspReportLinks links,
            TargetCatalog targets,
            ScanCatalog scans,
            IssueCatalog issues,
            AuditLogService audit,
            BrandingProperties branding,
            Clock clock) {
        this.reviews = reviews;
        this.links = links;
        this.targets = targets;
        this.scans = scans;
        this.issues = issues;
        this.audit = audit;
        this.branding = branding;
        this.clock = clock;
    }

    /** @throws NotFoundException for a hidden or absent repository, or one never reviewed */
    public OwaspReport latest(long repositoryId, Visibility allowed) {
        visible(repositoryId, allowed);
        AiReviewResultView review = reviews.latest(repositoryId).map(row -> AiReviewResultView.of(row, clock.instant()))
                .orElseThrow(() -> new NotFoundException(NO_REPORT));
        return linked(repositoryId, review, allowed);
    }

    /**
     * Runs a review and records that it was asked for.
     *
     * @param actor who asked, for the audit trail
     */
    public OwaspReport run(
            long repositoryId, Visibility allowed, String actor, String ipAddress, String userAgent) {

        RepositoryView repository = visible(repositoryId, allowed);
        AiReviewResultEntity result = reviews.run(repository);

        // **Audited like any outbound send.** This call puts the target's finding list — its
        // identifiers, its file paths — on a wire towards a host an operator configured. That it
        // is usually localhost is a deployment fact, not a property of the feature.
        audit.record(new AuditLogService.Record(
                AuditOperation.AI_REVIEW_REQUESTED,
                String.valueOf(repositoryId),
                "OWASP report requested (" + result.getModel() + ", " + result.getStatus() + ")",
                actor,
                ipAddress,
                userAgent));

        return linked(repositoryId, AiReviewResultView.of(result, clock.instant()), allowed);
    }

    /**
     * The last report as a PDF.
     *
     * <p><b>A failed run has no PDF.</b> Rendering "the model could not be reached" onto a cover
     * page with an OWASP title would produce an artefact that looks like a report and says
     * nothing — and unlike the screen, a file gets forwarded away from the context that explains
     * it. Refused with {@link OwaspReviewService.ReviewRefusedException}, 409 rather than 404: the
     * report exists, it just is not a document.
     */
    public byte[] pdf(long repositoryId, Visibility allowed) {
        RepositoryView repository = visible(repositoryId, allowed);
        AiReviewResultEntity row =
                reviews.latest(repositoryId).orElseThrow(() -> new NotFoundException(NO_REPORT));
        AiReviewResultView result = AiReviewResultView.of(row, clock.instant());

        if (AiReviewStatus.RUNNING.wireName().equals(result.status())) {
            throw new OwaspReviewService.ReviewRefusedException(
                    "The report is still being written. Export it once the model has answered.");
        }
        if (!AiReviewStatus.COMPLETED.wireName().equals(result.status())) {
            throw new OwaspReviewService.ReviewRefusedException(
                    "The last run did not produce a report: " + result.error());
        }

        ScanView scan = scans.scan(result.scanId()).orElse(null);
        return OwaspReportPdf.render(
                new OwaspReportPdf.Subject(
                        repository.name() == null ? RepositoryUrl.redact(repository.url()) : repository.name(),
                        repository.branch(),
                        scan == null ? null : scan.version(),
                        result.model(),
                        result.scanId(),
                        scan == null ? null : scan.createdAt(),
                        result.createdAt(),
                        issues.countByStateAndRepository(IssueState.OPEN.wireName(), repositoryId),
                        branding.name(),
                        OwaspReview.placedByRule(result.inputs())),
                result.response());
    }

    /** The review with the backlog's figures and the cited issues, as {@code allowed} sees them now. */
    private OwaspReport linked(long repositoryId, AiReviewResultView review, Visibility allowed) {
        return new OwaspReport(
                review,
                links.categoryFindings(repositoryId, allowed),
                links.issueLinks(repositoryId, review.evidenceIdentifiers(), allowed));
    }

    private RepositoryView visible(long repositoryId, Visibility allowed) {
        return RowVisibility.requireVisibleRepository(targets.repository(repositoryId).orElse(null), repositoryId, allowed);
    }
}
