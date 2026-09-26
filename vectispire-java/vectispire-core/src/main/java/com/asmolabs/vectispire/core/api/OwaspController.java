package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.aireview.OwaspMarkdown;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresWriteAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.services.compliance.OwaspReportService;
import com.asmolabs.vectispire.core.services.access.VisibilityService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
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

    private final OwaspReportService reports;
    private final VisibilityService visibility;

    public OwaspController(OwaspReportService reports, VisibilityService visibility) {
        this.reports = reports;
        this.visibility = visibility;
    }

    /**
     * @param status {@code completed} or {@code failed} — a failed run is returned, not hidden,
     *     so "the model could not be reached at 14:32" is on the screen instead of an empty page
     * @param model recorded on the row: a report is an artefact of the model that wrote it, and
     *     comparing two reports written by different models without knowing it is a trap
     * @param content the model's answer as it came, kept so nothing renders a report the raw text
     *     could contradict
     * @param inputs what the model was shown, kept beside what it answered. <b>This is what makes
     *     the report traceable rather than merely dated.</b> The prompt is a static instruction;
     *     the evidence digest is the half that decides what the prose says, and it cannot be
     *     recomputed later because the issues it was built from have moved on. Without it a reader
     *     can check when a claim was made and by which model, and nothing about what it was made
     *     from
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
            String inputs,
            Instant createdAt) {}

    @GetMapping
    public Report latest(@AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {
        return reportOf(reports.latest(
                id, visibility.of(principal.user().orElse(null), principal.credentialRestriction())));
    }

    @RequiresWriteAccount
    @PostMapping
    public Report run(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable long id,
            HttpServletRequest request) {

        return reportOf(reports.run(
                id,
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()),
                principal.user().map(user -> user.getUsername()).orElse("unknown"),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));
    }

    /**
     * The report as a document. A failed run has no PDF, and is answered 409 rather than 404 —
     * see {@link OwaspReportService#pdf}.
     */
    @GetMapping(value = "/export.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> pdf(@AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {
        byte[] document = reports.pdf(id, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));

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

    private static Report reportOf(AiReviewResultEntity result) {
        return new Report(
                result.getId(),
                result.getStatus(),
                result.getModel(),
                result.getResponse(),
                OwaspMarkdown.parse(result.getResponse()),
                result.getError(),
                result.getScanId(),
                result.getInputs(),
                result.getCreatedAt());
    }
}
