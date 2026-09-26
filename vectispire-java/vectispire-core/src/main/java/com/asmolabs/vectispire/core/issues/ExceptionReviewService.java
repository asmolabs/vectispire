package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import java.time.Instant;
import java.util.Optional;
import org.springframework.security.access.AccessDeniedException;
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

    private final IssueRepository issues;
    private final IssueTriageService triage;
    private final ExceptionsRegisterService register;

    public ExceptionReviewService(IssueRepository issues, IssueTriageService triage, ExceptionsRegisterService register) {
        this.issues = issues;
        this.triage = triage;
        this.register = register;
    }

    /**
     * @param reviewer who reviewed; empty for a caller that is not an account, which may not review
     * @throws AccessDeniedException for a reviewer whose role may not approve a triage decision —
     *     the platform governor among them
     * @throws java.util.NoSuchElementException for a hidden or absent issue, in the same words
     * @throws IllegalArgumentException when the issue carries no exception, or an extension names
     *     no date — see {@link IssueTriageService#review}
     */
    public ExceptionsRegisterService.Register review(
            long issueId,
            IssueTriageService.ReviewOutcome outcome,
            String comment,
            Optional<UserView> reviewer,
            Instant newExpiry,
            Visibility allowed) {

        // **A review is a triage decision, and only an approver takes one.** Confirming an
        // exception keeps an issue out of the gate; extending it does so for longer. The route's
        // marker admits the platform governor, whose role decides the rules and takes no decision
        // under them — the same refusal the VEX import makes. Checked first, before the issue is
        // read, so the answer does not depend on the body or on what exists. Four-eyes asks nothing
        // more here: it requires that a settled decision be an approver's, which this is.
        Optional<Role> role = reviewer.flatMap(user -> Role.of(user.role()));
        if (!role.map(Role::canApproveTriage).orElse(false)) {
            throw new AccessDeniedException(role.map(Role::governsPlatform).orElse(false)
                    ? "Reviewing an exception is a triage decision, and the platform governor takes none: "
                            + "it decides the rules the others act under."
                    : "Reviewing an exception is a triage decision, which this role may not approve.");
        }
        String actor = reviewer.map(UserView::username).orElse(null);

        // 404 rather than 403, like everywhere else here: a restricted reader must not learn that
        // an issue exists by being refused it.
        RowVisibility.requireVisibleIssue(issues.findById(issueId).orElse(null), IssueEntity::target, allowed);

        triage.review(issueId, outcome, comment, actor, newExpiry);

        return register.register(REGISTER_AFTER_REVIEW, null, allowed);
    }
}
