package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.issues.InvalidTriageException;
import com.asmolabs.zanshin.common.domain.issues.Triage;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.Issues;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Recording a human decision about an issue.
 *
 * <p>The service applies; the rules live in {@link Triage}. The separation is not decorative:
 * those rules are what a VEX document exports, and they have to be testable with no database.
 */
@Service
public class IssueTriageService {

    private final Issues issues;
    private final Clock clock;

    public IssueTriageService(Issues issues, Clock clock) {
        this.issues = issues;
        this.clock = clock;
    }

    /**
     * Throws {@link InvalidTriageException} on anything invalid, with a message meant to be
     * shown as it stands: it is the person triaging who has to know why their decision was
     * refused.
     */
    @Transactional
    public IssueEntity triage(long issueId, Triage.Request request) {
        // Validated **before** loading the issue: a malformed request must not cost a query,
        // and the message does not depend on the target existing.
        Triage.Decision decision = Triage.decide(request, clock.instant());

        IssueEntity issue = issues.findById(issueId)
                .orElseThrow(() -> new InvalidTriageException("Issue not found."));

        issue.setTriageStatus(decision.status().wireName());
        issue.setTriageJustification(
                decision.justification() == null ? null : decision.justification().wireName());
        issue.setTriageComment(decision.comment());
        issue.setTriagedBy(decision.triagedBy());
        issue.setTriagedAt(decision.triagedAt());
        issue.setTriageExpiresAt(decision.expiresAt().orElse(null));

        return issues.save(issue);
    }

    /**
     * Brings decisions that have reached their review date back under review.
     *
     * <p>Called from the maintenance tick and not on page load: a dismissal that expires
     * overnight has to stop dismissing in the VEX document a customer downloads and in the
     * verdict a pipeline asks for at three in the morning — not only when somebody opens the
     * screen.
     */
    @Transactional
    public List<Long> expireStale() {
        Instant now = clock.instant();
        List<IssueEntity> due = issues.findWithExpiredTriage(now);

        List<Long> expired = new ArrayList<>();
        for (IssueEntity issue : due) {
            TriageStatus status = TriageStatus.fromWireName(issue.getTriageStatus()).orElse(null);
            if (!Triage.isExpired(status, issue.getTriageExpiresAt(), now)) {
                // The query selects on the date alone. A row whose status is already `under_review`
                // — expired by an earlier pass, or written by hand — has nothing to expire, and
                // rewriting it would move `triagedAt` and erase who decided what.
                continue;
            }
            Triage.Expiry expiry = Triage.expire();
            issue.setTriageStatus(expiry.status().wireName());
            issue.setTriageExpiresAt(expiry.expiresAt());
            expired.add(issue.getId());
        }

        issues.saveAll(due);
        return List.copyOf(expired);
    }
}
