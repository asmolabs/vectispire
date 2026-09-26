package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.shared.RowVisibility;
import java.time.Instant;
import org.springframework.stereotype.Service;

/**
 * A periodic review of one exception, as the register's route performs it: refuse what the
 * reviewer may not see, apply the outcome, hand back the register as it now reads.
 *
 * <p><b>Apart from {@link ExceptionsRegisterService} on purpose.</b> That class assembles the
 * register for two readers — the screen and the evidence bundle — and reads nothing but what it
 * is given. The review is a write with an authorization check in front of it, and folding it in
 * would give the export path a mutation it never needs.
 */
@Service
public class ExceptionReviewService {

    /** What the screen shows after a review: the head of the register, as the list route opens it. */
    private static final int REGISTER_AFTER_REVIEW = 200;

    private final Issues issues;
    private final IssueTriageService triage;
    private final ExceptionsRegisterService register;

    public ExceptionReviewService(Issues issues, IssueTriageService triage, ExceptionsRegisterService register) {
        this.issues = issues;
        this.triage = triage;
        this.register = register;
    }

    /**
     * @param actor who reviewed; null for a caller that is not an account
     * @throws java.util.NoSuchElementException for a hidden or absent issue, in the same words
     * @throws IllegalArgumentException when the issue carries no exception, or an extension names
     *     no date — see {@link IssueTriageService#review}
     */
    public ExceptionsRegisterService.Register review(
            long issueId,
            IssueTriageService.ReviewOutcome outcome,
            String comment,
            String actor,
            Instant newExpiry,
            Visibility allowed) {

        // 404 rather than 403, like everywhere else here: a restricted reader must not learn that
        // an issue exists by being refused it.
        RowVisibility.requireVisible(issues.findById(issueId).orElse(null), allowed);

        triage.review(issueId, outcome, comment, actor, newExpiry);

        return register.register(REGISTER_AFTER_REVIEW, null, allowed);
    }
}
