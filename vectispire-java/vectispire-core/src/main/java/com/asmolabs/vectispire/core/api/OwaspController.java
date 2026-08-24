package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.aireview.OwaspMarkdown;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.OwaspReportPdf;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.OwaspReviewService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The OWASP posture report of one repository.
 *
 * <p><b>Repositories only, and the route says so rather than a guard.</b> The Top 10 is about an
 * application: half its categories — access control, insecure design, logging — describe code
 * and the decisions behind it. A container image has an inventory and a base distribution, and a
 * report grouping its CVEs under "Broken Access Control" would be a document with the right
 * headings and nothing behind them.
 */
@RestController
@RequestMapping("/api/v1/repositories/{id}/owasp-review")
@RequiresAccount
public class OwaspController {

    private final OwaspReviewService reviews;
    private final GitRepositories repositories;
    private final Scans scans;
    private final Issues issues;
    private final VisibilityService visibility;
    private final AuditLogService audit;

    public OwaspController(
            OwaspReviewService reviews,
            GitRepositories repositories,
            Scans scans,
            Issues issues,
            VisibilityService visibility,
            AuditLogService audit) {
        this.reviews = reviews;
        this.repositories = repositories;
        this.scans = scans;
        this.issues = issues;
        this.visibility = visibility;
        this.audit = audit;
    }

    /**
     * @param status {@code completed} or {@code failed} — a failed run is returned, not hidden,
     *     so "the model could not be reached at 14:32" is on the screen instead of an empty page
     * @param model recorded on the row: a report is an artefact of the model that wrote it, and
     *     comparing two reports written by different models without knowing it is a trap
     * @param content the model's answer as it came, kept so nothing renders a report the raw text
     *     could contradict
     * @param blocks the same answer parsed once, for a client that must place text into elements
     *     rather than interpret markup. Model prose derived from findings written by the audited
     *     repository is not something to hand a browser as HTML
     */
    public record Report(
            Long id,
            String status,
            String model,
            String content,
            List<OwaspMarkdown.Block> blocks,
            String error,
            Long scanId,
            Instant createdAt) {}

    @GetMapping
    public Report latest(@AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {
        visible(principal, id);
        return reviews.latest(id)
                .map(OwaspController::reportOf)
                .orElseThrow(() -> new NoSuchElementException("No OWASP report has been produced for this target."));
    }

    @PostMapping
    public Report run(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable long id,
            HttpServletRequest request) {

        RepositoryEntity repository = visible(principal, id);
        AiReviewResultEntity result = reviews.run(repository);

        // **Audited like any outbound send.** This call puts the target's finding list — its
        // identifiers, its file paths — on a wire towards a host an operator configured. That it
        // is usually localhost is a deployment fact, not a property of the feature.
        audit.record(new AuditLogService.Record(
                AuditOperation.AI_REVIEW_REQUESTED,
                String.valueOf(id),
                "OWASP report requested (" + result.getModel() + ", " + result.getStatus() + ")",
                principal.user().map(user -> user.getUsername()).orElse("unknown"),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return reportOf(result);
    }

    /**
     * The report as a document.
     *
     * <p><b>A failed run has no PDF.</b> Rendering "the model could not be reached" onto a cover
     * page with an OWASP title would produce an artefact that looks like a report and says
     * nothing — and unlike the screen, a file gets forwarded away from the context that explains
     * it. 409 rather than 404: the report exists, it just is not a document.
     */
    @GetMapping(value = "/export.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> pdf(@AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {
        RepositoryEntity repository = visible(principal, id);
        AiReviewResultEntity result = reviews.latest(id)
                .orElseThrow(() -> new NoSuchElementException("No OWASP report has been produced for this target."));

        if (!"completed".equals(result.getStatus())) {
            throw new OwaspReviewService.ReviewRefusedException(
                    "The last run did not produce a report: " + result.getError());
        }

        ScanEntity scan = scans.findById(result.getScanId()).orElse(null);
        byte[] document = OwaspReportPdf.render(
                new OwaspReportPdf.Subject(
                        repository.getName() == null ? repository.getUrl() : repository.getName(),
                        repository.getBranch(),
                        scan == null ? null : scan.getVersion(),
                        result.getModel(),
                        result.getScanId(),
                        scan == null ? null : scan.getCreatedAt(),
                        result.getCreatedAt(),
                        issues.countByStateAndRepository(IssueState.OPEN.wireName(), id)),
                result.getResponse());

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(
                        HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment()
                                .filename("vectispire-owasp-" + id + ".pdf")
                                .build()
                                .toString())
                .body(document);
    }

    private RepositoryEntity visible(VectispirePrincipal principal, long id) {
        RepositoryEntity repository = repositories.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Repository not found."));
        Visibilities.requireVisible(
                new ScanTarget.Repository(id),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
        return repository;
    }

    private static Report reportOf(AiReviewResultEntity result) {
        return new Report(
                result.getId(),
                result.getStatus(),
                result.getModel(),
                result.getResponse(),
                OwaspMarkdown.parse(result.getResponse()),
                result.getError(),
                result.getScanId(),
                result.getCreatedAt());
    }
}
