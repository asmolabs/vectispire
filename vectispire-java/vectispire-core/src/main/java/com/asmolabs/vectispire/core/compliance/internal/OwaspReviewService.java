package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.aireview.AiReviewStatus;
import com.asmolabs.vectispire.common.domain.aireview.OwaspReview;
import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.ai.AiReviewService;
import com.asmolabs.vectispire.core.compliance.OwaspCoverageService;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultRepository;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Producing the OWASP report, and recording that it was produced.
 *
 * <p><b>On demand, and after a scan only where an operator asked for it.</b> A model call takes
 * minutes on a local model, costs a GPU and answers slightly differently each time; hanging it off
 * every scan by default would fill the table with reports nobody read. It is a button, and — with
 * {@code ai_review_owasp_after_scan} on — a repository's completed scan asks for it too, one report
 * at a time, beside the scan and never inside it ({@link OwaspReportsAfterScans}). Either way the
 * report says which scan it was built from.
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

    /**
     * How long past the model's own timeout a running review is still waited for.
     *
     * <p>The HTTP client gives up at the timeout; what follows it — the second transaction, a pause of
     * the JVM — takes seconds. A minute is generous for that and short beside the timeout itself, so a
     * review whose process died is reported as failed a minute after it could no longer have
     * succeeded, not an hour later.
     */
    static final Duration SETTLING_MARGIN = Duration.ofMinutes(1);

    private final AiReviewService models;
    private final AiReviewResultRepository results;
    private final IssueCatalog issues;
    private final ScanCatalog scans;
    private final OwaspCoverageService coverage;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public OwaspReviewService(
            AiReviewService models,
            AiReviewResultRepository results,
            IssueCatalog issues,
            ScanCatalog scans,
            OwaspCoverageService coverage,
            TransactionTemplate transactions,
            Clock clock) {
        this.models = models;
        this.results = results;
        this.issues = issues;
        this.scans = scans;
        this.coverage = coverage;
        this.transactions = transactions;
        this.clock = clock;
    }

    /** Refused before anything is stored: an operator asking for a report has to be told why not. */
    public static class ReviewRefusedException extends ConflictException {
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
     *
     * <p><b>Three steps, and the call to the model is in none of the transactions.</b> This method
     * was one transaction around a request that may take five minutes — the configured timeout —
     * holding a connection from the pool and whatever the reads had locked for all of it. The
     * request is recorded {@code running} and committed first, so the
     * screen can say a report is being written; the model is asked with nothing open; its answer or
     * its failure is written by a second, short transaction. A process that stops between the first
     * and the last leaves a running row with a deadline — the timeout and {@link #SETTLING_MARGIN}
     * — past which it reads as failed and {@link #settleAbandoned} writes it so.
     *
     * <p>Not annotated, on purpose: an annotation here would put the call back inside a
     * transaction. The boundaries are {@link TransactionTemplate}s, opened and closed by this method.
     */
    public AiReviewResultEntity run(RepositoryView repository) {
        return review(repository, () -> scans.history(repository.id(), null, 1).stream()
                .findFirst()
                .orElseThrow(() -> new ReviewRefusedException(
                        "This repository has never been scanned. There is nothing to report on yet.")));
    }

    /**
     * Builds the report from one scan of the repository — the one whose completion asked for it.
     *
     * <p>The scan is named rather than read as the latest: a scan queued after the one that completed is
     * the latest and has found nothing yet, and a report built from it would date itself to a scan that
     * did not run.
     *
     * @throws ReviewRefusedException when model review is off, or the scan is no longer the repository's
     *     — purged by retention between its completion and this run
     */
    public AiReviewResultEntity runAfterScan(RepositoryView repository, long scanId) {
        return review(repository, () -> scans.scan(scanId)
                .filter(scan -> Long.valueOf(repository.id()).equals(scan.repoId()))
                .orElseThrow(() -> new ReviewRefusedException(
                        "Scan " + scanId + " of this repository no longer exists. There is nothing to report on.")));
    }

    /**
     * Whether a review of this repository is under way: its latest is running, and not yet past the
     * deadline by which whoever asked would have settled it.
     */
    @Transactional(readOnly = true)
    public boolean isRunning(long repositoryId) {
        return latest(repositoryId)
                .filter(row -> AiReviewStatus.RUNNING.wireName().equals(row.getStatus()))
                .filter(row -> !AiReviewStatus.isAbandoned(row.getStatus(), row.getDeadlineAt(), clock.instant()))
                .isPresent();
    }

    /**
     * Whether any review of any repository is under way, by this instance or another, asked for by a person
     * or by a scan — running, and not yet past its deadline.
     */
    @Transactional(readOnly = true)
    public boolean anyRunning() {
        return results.existsByStatusAndDeadlineAtAfter(AiReviewStatus.RUNNING.wireName(), clock.instant());
    }

    private AiReviewResultEntity review(RepositoryView repository, java.util.function.Supplier<ScanView> scanOf) {
        if (!models.isEnabled()) {
            throw new ReviewRefusedException(
                    "Model review is switched off. Turn it on under Settings → Model review.");
        }

        Duration timeout = models.timeout();
        AiReviewResultEntity requested = transactions.execute(status -> request(repository, scanOf.get(), timeout));

        String response = null;
        String error = null;
        try {
            response = models.reviewCode(requested.getInputs(), OwaspReview.PROMPT);
        } catch (RuntimeException failure) {
            // Recorded rather than rethrown: the screen shows the attempt and its reason, and an
            // operator can tell "the model refused" from "nobody ever asked".
            log.warn("OWASP report for repository {} failed: {}", repository.id(), failure.getMessage());
            error = truncate(failure.getMessage());
        }

        String answer = response;
        String reason = error;
        return transactions.execute(status -> settle(requested, answer, reason));
    }

    /**
     * The hourly sweep: every review still running past its deadline becomes a failed one.
     *
     * @return how many were settled
     */
    public int settleAbandoned() {
        return results.settleAbandoned(
                AiReviewStatus.RUNNING.wireName(),
                AiReviewStatus.FAILED.wireName(),
                AiReviewStatus.ABANDONED,
                clock.instant());
    }

    /** The first transaction: what the model will be shown, recorded as a review under way. */
    private AiReviewResultEntity request(RepositoryView repository, ScanView scan, Duration timeout) {
        List<IssueView> open = issues.ofRepositoryInState(repository.id(), IssueState.OPEN.wireName());
        List<OwaspReview.Evidence> evidence = open.stream().map(OwaspReviewService::evidenceOf).toList();
        String digest = OwaspReview.digest(
                new OwaspReview.Subject(
                        repository.name() == null ? RepositoryUrl.redact(repository.url()) : repository.name(),
                        repository.branch(),
                        scan.version(),
                        open.size(),
                        coverageOf(repository)),
                evidence,
                MAX_EVIDENCE);

        Instant now = clock.instant();
        AiReviewResultEntity result = new AiReviewResultEntity();
        result.setScanId(scan.id());
        result.setRepoId(scan.repoId());
        result.setModel(models.selectedModel());
        result.setPrompt(OwaspReview.PROMPT);
        // **Kept, because a report nobody can trace to its input is not evidence of anything.**
        // The prompt is the instruction; this is what the model was shown, and the two answer
        // different questions about a document somebody may have to defend.
        result.setInputs(digest);
        // The same findings in a form the report's links read, from the same list and limit as the
        // digest: what the links may point at is what the model was shown, never what its prose names.
        result.setEvidenceIdentifiers(
                EvidenceIdentifiers.write(OwaspReview.identifiersShown(evidence, MAX_EVIDENCE)));
        result.setCreatedAt(now);
        result.setStatus(AiReviewStatus.RUNNING.wireName());
        result.setDeadlineAt(now.plus(timeout).plus(SETTLING_MARGIN));
        return results.save(result);
    }

    /**
     * The second transaction: what the model answered, or why it did not.
     *
     * <p>Written over whatever the row says now — the sweep included, should this request have
     * outlived its deadline: an answer that did arrive is truer than "nothing was waiting for it".
     * A row gone in the meantime — its scan purged by retention while the model wrote — is not
     * written again: its target's history no longer holds the scan it described, and the caller
     * still receives what the model said.
     */
    private AiReviewResultEntity settle(AiReviewResultEntity requested, String response, String error) {
        AiReviewResultEntity row = results.findById(requested.getId()).orElse(null);
        AiReviewResultEntity result = row == null ? requested : row;
        result.setDeadlineAt(null);
        if (error == null) {
            result.setResponse(response);
            result.setStatus(AiReviewStatus.COMPLETED.wireName());
        } else {
            result.setStatus(AiReviewStatus.FAILED.wireName());
            result.setError(error);
        }
        return row == null ? result : results.save(result);
    }

    /**
     * The repository's OWASP grid, one state per category — the grid the compliance screen shows for this
     * repository alone, so the report's "nothing here" says the same as the screen beside it.
     */
    private Map<String, OwaspCoverage.State> coverageOf(RepositoryView repository) {
        Map<String, OwaspCoverage.State> states = new LinkedHashMap<>();
        coverage.ofTarget(new ScanTarget.Repository(repository.id()), coverage.reading())
                .forEach(line -> states.put(line.id(), line.state()));
        return states;
    }

    private static OwaspReview.Evidence evidenceOf(IssueView issue) {
        String component = issue.packageName() == null
                ? null
                : issue.packageVersion() == null
                        ? issue.packageName()
                        : issue.packageName() + " " + issue.packageVersion();

        return new OwaspReview.Evidence(
                issue.type(),
                issue.severity(),
                issue.identifier(),
                component,
                issue.filePath(),
                issue.triageStatus(),
                issue.description(),
                // The rule's declaration as the issue carries it; the digest places it as the grid does.
                issue.owaspCategory());
    }

    /** The column is 500, and a stack-trace message routinely exceeds it. */
    private static String truncate(String message) {
        if (message == null) {
            return "The model call failed with no message.";
        }
        return message.length() <= 500 ? message : message.substring(0, 497) + "…";
    }
}
