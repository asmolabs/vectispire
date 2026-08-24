package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.aireview.OwaspReview;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.core.persistence.AiReviewResultEntity;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.AiReviewResults;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.Scans;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Producing the OWASP report, and recording that it was produced.
 *
 * <p><b>On demand, never on a scan.</b> A model call takes tens of seconds, costs a GPU and
 * answers slightly differently each time; hanging it off every scan would make the queue
 * unpredictable and fill the table with reports nobody read. It is a button, and the report says
 * which scan it was built from.
 *
 * <p><b>The failure is stored, not thrown away.</b> A row is written whether the model answers
 * or not: "the report could not be produced, here is why, at this time" is what an operator
 * needs to see on the screen, and a run that vanishes silently is the failure mode this codebase
 * spends most of its comments guarding against.
 */
@Service
public class OwaspReviewService {

    private static final Logger log = LoggerFactory.getLogger(OwaspReviewService.class);

    /**
     * Findings sent to the model, at most.
     *
     * <p>Enough to characterise a backlog, small enough to fit a local model's context beside a
     * long instruction. What is left out is stated in the digest, so the report describes a
     * sample and says so.
     */
    private static final int MAX_EVIDENCE = 300;

    private static final String STATUS_OK = "completed";
    private static final String STATUS_FAILED = "failed";

    private final AiReviewService models;
    private final AiReviewResults results;
    private final Issues issues;
    private final Scans scans;
    private final Clock clock;

    public OwaspReviewService(
            AiReviewService models, AiReviewResults results, Issues issues, Scans scans, Clock clock) {
        this.models = models;
        this.results = results;
        this.issues = issues;
        this.scans = scans;
        this.clock = clock;
    }

    /** Refused before anything is stored: an operator asking for a report has to be told why not. */
    public static class ReviewRefusedException extends RuntimeException {
        public ReviewRefusedException(String message) {
            super(message);
        }
    }

    @Transactional(readOnly = true)
    public Optional<AiReviewResultEntity> latest(long repositoryId) {
        return results.latestForRepository(repositoryId, Limit.of(1)).stream().findFirst();
    }

    /**
     * Builds the report for a repository's most recent scan.
     *
     * <p><b>A scan is required, and that is not a technicality.</b> The report is a statement
     * about a version at a date; produced from a target nobody ever scanned it would be a
     * document asserting an absence of findings that nothing looked for — the same trap the
     * posture PDF names, in a format that reads even more like a verdict.
     */
    @Transactional
    public AiReviewResultEntity run(RepositoryEntity repository) {
        if (!models.isEnabled()) {
            throw new ReviewRefusedException(
                    "Model review is switched off. Turn it on under Settings → Model review.");
        }

        ScanEntity scan = scans.findHistory(repository.getId(), null, Limit.of(1)).stream()
                .findFirst()
                .orElseThrow(() -> new ReviewRefusedException(
                        "This repository has never been scanned. There is nothing to report on yet."));

        List<IssueEntity> open = issues.findByRepositoryAndState(repository.getId(), IssueState.OPEN.wireName());
        String digest = OwaspReview.digest(
                new OwaspReview.Subject(
                        repository.getName() == null ? repository.getUrl() : repository.getName(),
                        repository.getBranch(),
                        scan.getVersion(),
                        open.size()),
                open.stream().map(OwaspReviewService::evidenceOf).toList(),
                MAX_EVIDENCE);

        AiReviewResultEntity result = new AiReviewResultEntity();
        result.setScanId(scan.getId());
        result.setModel(models.selectedModel());
        result.setPrompt(OwaspReview.PROMPT);
        result.setCreatedAt(clock.instant());

        try {
            result.setResponse(models.reviewCode(digest, OwaspReview.PROMPT));
            result.setStatus(STATUS_OK);
        } catch (RuntimeException failure) {
            // Recorded rather than rethrown: the screen shows the attempt and its reason, and an
            // operator can tell "the model refused" from "nobody ever asked".
            log.warn("OWASP report for repository {} failed: {}", repository.getId(), failure.getMessage());
            result.setStatus(STATUS_FAILED);
            result.setError(truncate(failure.getMessage()));
        }
        return results.save(result);
    }

    private static OwaspReview.Evidence evidenceOf(IssueEntity issue) {
        String component = issue.getPackageName() == null
                ? null
                : issue.getPackageVersion() == null
                        ? issue.getPackageName()
                        : issue.getPackageName() + " " + issue.getPackageVersion();

        return new OwaspReview.Evidence(
                issue.getType(),
                issue.getSeverity(),
                issue.getIdentifier(),
                component,
                issue.getFilePath(),
                issue.getTriageStatus(),
                issue.getDescription());
    }

    /** The column is 500, and a stack-trace message routinely exceeds it. */
    private static String truncate(String message) {
        if (message == null) {
            return "The model call failed with no message.";
        }
        return message.length() <= 500 ? message : message.substring(0, 497) + "…";
    }
}
