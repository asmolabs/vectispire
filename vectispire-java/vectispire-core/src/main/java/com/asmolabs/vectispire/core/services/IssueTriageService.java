package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.issues.InvalidTriageException;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
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

    private static final String APPROVAL = "approval";

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
        return triage(issueId, request, true);
    }

    @Transactional
    public IssueEntity triage(long issueId, Triage.Request request, boolean canApprove) {
        Triage.Decision decision = queueIfNotApprover(Triage.decide(request, clock.instant()), canApprove);

        IssueEntity issue = issues.findById(issueId)
                .orElseThrow(() -> new InvalidTriageException("Issue not found."));

        return issues.save(apply(issue, decision));
    }

    /**
     * The same decision on several issues, or on none.
     */
    @Transactional
    public List<IssueEntity> triageAll(List<Long> issueIds, Triage.Request request) {
        return triageAll(issueIds, request, true);
    }

    @Transactional
    public List<IssueEntity> triageAll(List<Long> issueIds, Triage.Request request, boolean canApprove) {
        Triage.Decision decision = queueIfNotApprover(Triage.decide(request, clock.instant()), canApprove);

        List<IssueEntity> triaged = new ArrayList<>(issueIds.size());
        for (Long issueId : issueIds) {
            IssueEntity issue = issues.findById(issueId)
                    .orElseThrow(() -> new InvalidTriageException("Issue " + issueId + " not found."));
            triaged.add(apply(issue, decision));
        }
        return issues.saveAll(triaged);
    }

    /**
     * Sends a settling decision to the approval queue when its author cannot approve.
     *
     * <p><b>Both settling statuses, not just the dismissal.</b> The test was
     * {@code == NOT_AFFECTED}, and {@link TriageStatus} marks two statuses as settling: an issue
     * declared {@code FIXED} stops failing builds exactly as a dismissed one does. So four-eyes
     * held the door a non-approver was most likely to be refused at, and left the other one open —
     * a reader could not argue an issue away, and could declare it repaired, alone, in one request.
     * The setting's own help text promised both.
     *
     * <p>Asking {@link TriageStatus#isSettled()} rather than naming the statuses again is the
     * point: the property already means "takes this out of the gate verdict", so a status added
     * later is covered the day it is marked settling, instead of the day somebody remembers this
     * line.
     *
     * <p><b>Applied after {@link Triage#decide}, and that ordering is the whole subtlety.</b>
     * {@code decide} requires a VEX justification for {@code PENDING_APPROVAL}, which was sound
     * while the queue could only hold exemptions — a dismissal with no justification exports as an
     * invalid VEX statement. A queued <em>fix</em> is not an exemption and needs no such
     * justification. Validating what the operator actually asked for and queueing the result
     * afterwards keeps both rules true: a dismissal still cannot reach the queue without its
     * justification, and a fix is no longer asked for one it has no way to give.
     */
    private static Triage.Decision queueIfNotApprover(Triage.Decision decision, boolean canApprove) {
        if (canApprove || decision.status() == null || !decision.status().isSettled()) {
            return decision;
        }
        return new Triage.Decision(
                TriageStatus.PENDING_APPROVAL,
                decision.justification(),
                decision.comment(),
                decision.triagedBy(),
                decision.triagedAt(),
                decision.expiresAt());
    }

    /**
     * Writes one decision onto one issue, history included.
     */
    private IssueEntity apply(IssueEntity issue, Triage.Decision decision) {
        String previous = issue.getTriageStatus();
        // Settling, not dismissing — the counterpart of the widening in `queueIfNotApprover`. Without
        // it a queued `FIXED` would be granted as an ordinary edit: no approval recorded in the
        // history, and `requireASecondPairOfEyes` never reached, so the requester could grant it.
        String origin = (TriageStatus.PENDING_APPROVAL.wireName().equals(previous)
                && decision.status() != null && decision.status().isSettled()) ? APPROVAL : MANUAL;

        if (APPROVAL.equals(origin)) {
            requireASecondPairOfEyes(issue, decision);
        }

        issue.setTriageStatus(decision.status().wireName());
        issue.setTriageJustification(
                decision.justification() == null ? null : decision.justification().wireName());
        issue.setTriageComment(decision.comment());
        issue.setTriagedBy(decision.triagedBy());
        issue.setTriagedAt(decision.triagedAt());
        issue.setTriageExpiresAt(decision.expiresAt().orElse(null));

        events.save(event(
                issue,
                previous,
                decision.status().wireName(),
                decision.justification() == null ? null : decision.justification().wireName(),
                decision.comment(),
                decision.triagedBy(),
                origin,
                decision.triagedAt(),
                decision.expiresAt().orElse(null)));

        return issue;
    }

    /**
     * Four eyes, counted as two people rather than as two roles.
     *
     * <p><b>What the role gate alone does not do.</b> {@link #queueIfNotApprover} downgrades a
     * dismissal to {@code PENDING_APPROVAL} when its author cannot approve, which produces a
     * queue — and nothing after that compared the approver to the requester. A Security
     * Champion could therefore raise an exemption and approve it in the same session, and the
     * control still reported itself as satisfied. That is a maker-checker <em>role</em> gate;
     * it is not four eyes, and DORA Art. 9 and NIS 2 Art. 21 are read literally by the people
     * who audit against them.
     *
     * <p>The requester is read from the history rather than from the issue: {@code triagedBy}
     * on the row is overwritten by each decision, so by the time the approval arrives the row
     * already says who is approving. The event log is the only place that still remembers who
     * asked.
     *
     * <p><b>The one case this lets through, deliberately.</b> An exemption requested before
     * this check existed may carry no actor at all, and refusing those would strand them with
     * no way forward — the request cannot be re-made without first being approved. An unknown
     * requester is therefore admitted. Every request created since carries the authenticated
     * username, or the literal {@code unknown} the controller substitutes, and two of those
     * compare equal — so the gap closes as the old rows are worked off rather than staying
     * open.
     */
    private void requireASecondPairOfEyes(IssueEntity issue, Triage.Decision decision) {
        String requester = lastApprovalRequester(issue);
        if (requester == null || requester.isBlank()) {
            return;
        }

        String approver = decision.triagedBy();
        if (approver != null && requester.trim().equalsIgnoreCase(approver.trim())) {
            throw new InvalidTriageException(
                    "Four-eyes approval: this exemption was requested by " + requester
                            + ", so it has to be approved by somebody else.");
        }
    }

    /** The actor of the most recent request that put this issue into the approval queue. */
    private String lastApprovalRequester(IssueEntity issue) {
        List<TriageEventEntity> history =
                events.findByIssueIdOrderByOccurredAtAscIdAsc(issue.getId());

        String requester = null;
        for (TriageEventEntity event : history) {
            if (TriageStatus.PENDING_APPROVAL.wireName().equals(event.getToStatus())) {
                // Oldest first, so the last match is the request being answered now.
                requester = event.getActor();
            }
        }
        return requester;
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
