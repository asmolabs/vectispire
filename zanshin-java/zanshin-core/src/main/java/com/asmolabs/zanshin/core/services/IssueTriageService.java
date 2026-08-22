package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.issues.InvalidTriageException;
import com.asmolabs.zanshin.common.domain.issues.Triage;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.TriageEventEntity;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.TriageEvents;
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

    /** What took the decision, for a report that must not attribute a lapse to a person. */
    private static final String MANUAL = "manual";

    private static final String EXPIRY = "expiry";

    private final Issues issues;
    private final TriageEvents events;
    private final Clock clock;

    public IssueTriageService(Issues issues, TriageEvents events, Clock clock) {
        this.issues = issues;
        this.events = events;
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

        return issues.save(apply(issue, decision));
    }

    /**
     * The same decision on several issues, or on none.
     *
     * <p><b>Why this exists.</b> One CVE appears in forty repositories, and "not reachable in our
     * configuration" is one judgement about one context — not forty. Deciding it forty times is
     * how a backlog stops being triaged at all, which makes the whole tracking pointless: an
     * untriaged backlog is a list, and a list is what Zanshin exists not to be.
     *
     * <p><b>All or nothing, in one transaction.</b> A partial success would leave the caller
     * holding a decision that applied to an unknown subset — and the obvious recovery, sending it
     * again, would re-triage what already succeeded and move every {@code triagedAt} it touched.
     * So one bad identifier refuses the batch and names itself.
     *
     * <p><b>Each issue still gets its own history event.</b> That is the whole point of doing this
     * here rather than with an {@code update … where id in (…)}: the triage history is what a
     * compliance reader is handed, and a bulk decision that left forty issues changed with no
     * recorded transition would be indistinguishable from forty rows somebody edited by hand.
     *
     * @param issueIds in the caller's order. Duplicates are not de-duplicated — a caller sending
     *     the same id twice has a bug this method cannot fix by hiding it, and the second write
     *     would produce a second history event from a state to itself
     */
    @Transactional
    public List<IssueEntity> triageAll(List<Long> issueIds, Triage.Request request) {
        Triage.Decision decision = Triage.decide(request, clock.instant());

        List<IssueEntity> triaged = new ArrayList<>(issueIds.size());
        for (Long issueId : issueIds) {
            IssueEntity issue = issues.findById(issueId)
                    // Names the identifier, because "Issue not found" about a batch of forty tells
                    // the person triaging nothing they can act on.
                    .orElseThrow(() -> new InvalidTriageException("Issue " + issueId + " not found."));
            triaged.add(apply(issue, decision));
        }
        return issues.saveAll(triaged);
    }

    /**
     * Writes one decision onto one issue, history included.
     *
     * <p>Shared by the single and the bulk route so that a decision cannot mean two things
     * depending on how many issues it was applied to — the transition recorded, the expiry, the
     * actor. Saving is the caller's, so a batch is one flush rather than N.
     */
    private IssueEntity apply(IssueEntity issue, Triage.Decision decision) {
        // **Read before the write, or the transition has no left half.** The whole value of the
        // history is "it was under review, it became accepted"; capturing the previous status
        // after the assignment would record a decision from a state to itself.
        String previous = issue.getTriageStatus();

        issue.setTriageStatus(decision.status().wireName());
        issue.setTriageJustification(
                decision.justification() == null ? null : decision.justification().wireName());
        issue.setTriageComment(decision.comment());
        issue.setTriagedBy(decision.triagedBy());
        issue.setTriagedAt(decision.triagedAt());
        issue.setTriageExpiresAt(decision.expiresAt().orElse(null));

        // Written in the same transaction as the decision: a history missing the change it is
        // supposed to prove is worse than no history, because nothing says it is missing.
        events.save(event(
                issue,
                previous,
                decision.status().wireName(),
                decision.justification() == null ? null : decision.justification().wireName(),
                decision.comment(),
                decision.triagedBy(),
                MANUAL,
                decision.triagedAt(),
                decision.expiresAt().orElse(null)));

        return issue;
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
            String previous = issue.getTriageStatus();
            issue.setTriageStatus(expiry.status().wireName());
            issue.setTriageExpiresAt(expiry.expiresAt());
            expired.add(issue.getId());

            // **Recorded like a human decision, and marked as not being one.** An acceptance
            // that lapsed overnight changes what the gate answers and what a VEX document
            // asserts; a history that showed only deliberate decisions would present that
            // change as having no cause. The actor stays null — inventing a "system" user would
            // put a person who does not exist in a compliance report.
            events.save(event(
                    issue,
                    previous,
                    expiry.status().wireName(),
                    issue.getTriageJustification(),
                    null,
                    null,
                    EXPIRY,
                    now,
                    expiry.expiresAt()));
        }

        issues.saveAll(due);
        return List.copyOf(expired);
    }

    private static TriageEventEntity event(
            IssueEntity issue,
            String from,
            String to,
            String justification,
            String comment,
            String actor,
            String origin,
            Instant at,
            Instant expiresAt) {

        TriageEventEntity event = new TriageEventEntity();
        event.setIssueId(issue.getId());
        // The column is not nullable and a row written before triage ever ran carries no status.
        // `under_review` is what such an issue behaves as, so it is what the history should say
        // it left — not an empty cell a reader has to interpret.
        event.setFromStatus(from == null || from.isBlank() ? TriageStatus.UNDER_REVIEW.wireName() : from);
        event.setToStatus(to);
        event.setJustification(justification);
        event.setComment(comment);
        event.setActor(actor);
        event.setOrigin(origin);
        event.setOccurredAt(at);
        event.setExpiresAt(expiresAt);
        // The version the decision was taken against, which is what makes "accepted on 2.4.1,
        // still open on 2.5.0" a sentence the screen can produce.
        event.setScanId(issue.getLastSeenScanId());
        return event;
    }
}
