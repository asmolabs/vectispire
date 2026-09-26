package com.asmolabs.vectispire.core.services.compliance;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.core.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.audit.AuditLogService;
import com.asmolabs.vectispire.core.services.settings.BrandingProperties;
import com.asmolabs.vectispire.core.services.access.RowVisibility;
import java.util.NoSuchElementException;
import org.springframework.stereotype.Service;

/**
 * One repository's OWASP report, as the routes serve it: read, requested, rendered.
 *
 * <p>{@link OwaspReviewService} writes the report; this class decides who may reach it and what
 * surrounds it — the visibility refusal, the audit entry for a run, the cover page of the PDF.
 * Every entry point takes the caller's visibility, so a repository they were not given reads as
 * one that does not exist, on all three.
 */
@Service
public class OwaspReportService {

    private static final String NO_REPORT = "No OWASP report has been produced for this target.";

    private final OwaspReviewService reviews;
    private final GitRepositories repositories;
    private final Scans scans;
    private final Issues issues;
    private final AuditLogService audit;
    private final BrandingProperties branding;

    public OwaspReportService(
            OwaspReviewService reviews,
            GitRepositories repositories,
            Scans scans,
            Issues issues,
            AuditLogService audit,
            BrandingProperties branding) {
        this.reviews = reviews;
        this.repositories = repositories;
        this.scans = scans;
        this.issues = issues;
        this.audit = audit;
        this.branding = branding;
    }

    /** @throws NoSuchElementException for a hidden or absent repository, or one never reviewed */
    public AiReviewResultView latest(long repositoryId, Visibility allowed) {
        visible(repositoryId, allowed);
        return reviews.latest(repositoryId).map(AiReviewResultView::of)
                .orElseThrow(() -> new NoSuchElementException(NO_REPORT));
    }

    /**
     * Runs a review and records that it was asked for.
     *
     * @param actor who asked, for the audit trail
     */
    public AiReviewResultView run(
            long repositoryId, Visibility allowed, String actor, String ipAddress, String userAgent) {

        RepositoryEntity repository = visible(repositoryId, allowed);
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

        return AiReviewResultView.of(result);
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
        RepositoryEntity repository = visible(repositoryId, allowed);
        AiReviewResultEntity result =
                reviews.latest(repositoryId).orElseThrow(() -> new NoSuchElementException(NO_REPORT));

        if (!"completed".equals(result.getStatus())) {
            throw new OwaspReviewService.ReviewRefusedException(
                    "The last run did not produce a report: " + result.getError());
        }

        ScanEntity scan = scans.findById(result.getScanId()).orElse(null);
        return OwaspReportPdf.render(
                new OwaspReportPdf.Subject(
                        repository.getName() == null ? RepositoryUrl.redact(repository.getUrl()) : repository.getName(),
                        repository.getBranch(),
                        scan == null ? null : scan.getVersion(),
                        result.getModel(),
                        result.getScanId(),
                        scan == null ? null : scan.getCreatedAt(),
                        result.getCreatedAt(),
                        issues.countByStateAndRepository(IssueState.OPEN.wireName(), repositoryId),
                        branding.name()),
                result.getResponse());
    }

    private RepositoryEntity visible(long repositoryId, Visibility allowed) {
        return RowVisibility.requireVisible(repositories.findById(repositoryId).orElse(null), allowed);
    }
}
