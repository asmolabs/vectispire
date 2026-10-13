package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.issues.InvalidTriageException;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageOrigin;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventEntity;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.dao.OptimisticLockingFailureException;
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
    private static final String MANUAL = TriageOrigin.MANUAL.wireName();

    private static final String APPROVAL = TriageOrigin.APPROVAL.wireName();

    private static final String EXPIRY = TriageOrigin.EXPIRY.wireName();

    /**
     * A periodic review of an exception, which may change nothing.
     *
     * <p><b>Its own origin because a review that confirms is the one an assessment asks for and
     * the one nothing recorded.</b> Every other entry in this history exists because a status
     * moved; somebody looking at an acceptance in March, judging it still sound and leaving it
     * alone left no trace at all. An assessor reading "accepted in January, expires in December"
     * cannot tell a decision revisited quarterly from one nobody has opened since — and the
     * difference between those two is the whole of clause 8.1.
     */
    private static final String REVIEW = TriageOrigin.REVIEW.wireName();

    private final IssueRepository issues;
    private final TriageEventRepository events;
    private final Clock clock;

    public IssueTriageService(IssueRepository issues, TriageEventRepository events, Clock clock) {
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
        Queued decision = queueIfNotApprover(Triage.decide(request, clock.instant()), canApprove);

        IssueEntity issue = issues.findById(issueId)
                .orElseThrow(() -> new InvalidTriageException("Issue not found."));

        return written(() -> issues.saveAndFlush(apply(issue, decision)));
    }

    /**
     * {@link #triage(long, Triage.Request, boolean)} as another module sees its result: the issue's
     * view. Transactional itself, since the call below does not go through the proxy; it is the one
     * the tracker's webhook uses, and the entity stays this module's (decision 0029).
     */
    @Transactional
    public IssueView triageView(long issueId, Triage.Request request, boolean canApprove) {
        return IssueView.of(triage(issueId, request, canApprove));
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
        Queued decision = queueIfNotApprover(Triage.decide(request, clock.instant()), canApprove);

        Map<Long, IssueEntity> read = readAll(issueIds);
        List<IssueEntity> triaged = new ArrayList<>(issueIds.size());
        for (Long issueId : issueIds) {
            IssueEntity issue = read.get(issueId);
            if (issue == null) {
                throw new InvalidTriageException("Issue " + issueId + " not found.");
            }
            triaged.add(apply(issue, decision));
        }
        return written(() -> issues.saveAllAndFlush(triaged));
    }

    /** What a bulk decision wrote, and the status each issue had before it — in the order asked. */
    public record BulkTriage(List<String> previous, List<IssueEntity> triaged) {}

    /**
     * The same decision on several issues a caller named, each refused as absent when it may not see
     * it — every one checked before the first is written.
     *
     * <p><b>One read, one transaction.</b> The route read each issue by its id to check it, then this
     * class read each one again to write it, in another transaction: a thousand statements for 500
     * issues, and a check made on a row the write did not hold. The issues are read in one statement
     * here, and the rows checked are the rows written — so a scan or a person writing one of them
     * between the check and the write is refused by the revision (409 {@code issue-changed-meanwhile}),
     * the whole batch with it, where it went unseen when it fell before the second read.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException absent and hidden alike,
     *     before the decision itself is judged — as the route always answered
     */
    @Transactional
    public BulkTriage triageVisible(
            List<Long> issueIds, Triage.Request request, boolean canApprove, Visibility visibility) {
        Map<Long, IssueEntity> read = readAll(issueIds);
        List<String> previous = new ArrayList<>(issueIds.size());
        for (Long issueId : issueIds) {
            previous.add(String.valueOf(RowVisibility.requireVisibleIssue(read.get(issueId), IssueEntity::target, visibility)
                    .getTriageStatus()));
        }

        Queued decision = queueIfNotApprover(Triage.decide(request, clock.instant()), canApprove);
        List<IssueEntity> triaged = new ArrayList<>(issueIds.size());
        for (Long issueId : issueIds) {
            triaged.add(apply(read.get(issueId), decision));
        }
        return new BulkTriage(previous, written(() -> issues.saveAllAndFlush(triaged)));
    }

    /**
     * The issues named, by id, in one statement — at most the backlog page's 500, well inside every
     * engine's bind limit. A repeated id is one row, applied as often as it was named, as it was.
     */
    private Map<Long, IssueEntity> readAll(List<Long> issueIds) {
        return issues.findAllById(issueIds).stream()
                .collect(Collectors.toMap(IssueEntity::getId, Function.identity()));
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
    private static Queued queueIfNotApprover(Triage.Decision decision, boolean canApprove) {
        if (canApprove || decision.status() == null || !decision.status().isSettled()) {
            return new Queued(decision, null);
        }
        // **The status asked for travels with the queue.** It was dropped here, keeping the
        // justification, the comment and the review date: the approver then saw `pending_approval`
        // and chose, and a tracker's "Won't Fix" could be granted as `not_affected` — a signed
        // "not exposed" nobody had asked for (decision 0041).
        return new Queued(new Triage.Decision(
                TriageStatus.PENDING_APPROVAL,
                decision.justification(),
                decision.comment(),
                decision.triagedBy(),
                decision.triagedAt(),
                decision.expiresAt()), decision.status());
    }

    /**
     * A decision as it is written, and — when it was queued for approval — the settled status it asked
     * for, which {@link #apply} keeps on the issue and on the history row until somebody answers.
     */
    private record Queued(Triage.Decision decision, TriageStatus requested) {}

    /**
     * Would settling this issue as {@code status} answer a request that asked for another one?
     *
     * <p>Only a request that recorded what it asked for can be contradicted: one queued before V88, or
     * a {@code pending_approval} asked for directly, names nothing, and is granted as the approver
     * chooses — as it always was.
     */
    static boolean contradictsTheRequest(IssueEntity issue, TriageStatus status) {
        return TriageStatus.PENDING_APPROVAL.wireName().equals(issue.getTriageStatus())
                && status != null && status.isSettled()
                && issue.getTriageRequestedStatus() != null
                && !issue.getTriageRequestedStatus().equals(status.wireName());
    }

    /**
     * Writes one decision onto one issue, history included.
     */
    private IssueEntity apply(IssueEntity issue, Queued queued) {
        Triage.Decision decision = queued.decision();
        String previous = issue.getTriageStatus();
        // Settling, not dismissing — the counterpart of the widening in `queueIfNotApprover`. Without
        // it a queued `FIXED` would be granted as an ordinary edit: no approval recorded in the
        // history, and `requireASecondPairOfEyes` never reached, so the requester could grant it.
        String origin = (TriageStatus.PENDING_APPROVAL.wireName().equals(previous)
                && decision.status() != null && decision.status().isSettled()) ? APPROVAL : MANUAL;

        if (APPROVAL.equals(origin)) {
            requireASecondPairOfEyes(issue, decision);
            // **Granted as asked, or turned down.** Four eyes on a status the second pair chose is
            // one pair of eyes on that status: the requester never asked for it. An approver who
            // disagrees answers `under_review` or `affected`, which is no approval, and decides after.
            if (contradictsTheRequest(issue, decision.status())) {
                throw new TriageApprovalDiffersException(issue.getTriageRequestedStatus(), decision.status());
            }
        }

        issue.setTriageStatus(decision.status().wireName());
        issue.setTriageJustification(
                decision.justification() == null ? null : decision.justification().wireName());
        issue.setTriageComment(decision.comment());
        issue.setTriagedBy(decision.triagedBy());
        issue.setTriagedAt(decision.triagedAt());
        issue.setTriageExpiresAt(decision.expiresAt().orElse(null));
        // Kept while the issue waits, cleared by any other decision: a request answered, withdrawn or
        // turned down asks for nothing any more.
        String requested = queued.requested() == null ? null : queued.requested().wireName();
        issue.setTriageRequestedStatus(requested);

        TriageEventEntity recorded = event(
                issue,
                previous,
                decision.status().wireName(),
                decision.justification() == null ? null : decision.justification().wireName(),
                decision.comment(),
                decision.triagedBy(),
                origin,
                decision.triagedAt(),
                decision.expiresAt().orElse(null));
        recorded.setRequestedStatus(requested);
        events.save(recorded);

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
     * username, or the literal {@code unknown} {@code IssueDecisionService} substitutes, and two of those
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

    /** What a reviewer concluded about an exception they were asked to look at again. */
    public enum ReviewOutcome {
        /** It still holds, unchanged. The entry exists so that "somebody looked" is a fact. */
        CONFIRMED,
        /** It still holds, with a new date. */
        EXTENDED,
        /** It does not hold any more; the issue goes back under review and the gate stops honouring it. */
        REVOKED
    }

    /**
     * Records that somebody revisited an exception, and applies what they concluded.
     *
     * <p><b>A confirmation writes a row that changes nothing, and that is the point.</b> The
     * register could always show when an exception was granted and when it expires; it could never
     * show that anybody had looked at it in between. Periodic review is the control ISO 27001
     * clause 8.1 asks about, and it was the one activity in this product that left no evidence
     * precisely when it was performed correctly.
     *
     * <p>Written into the issue's own history rather than a table of its own, because an assessor
     * reads one timeline per exception and merging two sources at read time is how the two come to
     * disagree. The origin is what separates a review from a decision.
     *
     * @param newExpiry required to extend, ignored otherwise
     * @throws InvalidInputException when the issue carries no exception to review
     */
    @Transactional
    public IssueEntity review(
            long issueId, ReviewOutcome outcome, String comment, String actor, Instant newExpiry) {

        // Before anything is read: a body without an outcome reached the switch below and answered
        // 500 with a NullPointerException, which told the reviewer nothing about what was missing.
        if (outcome == null) {
            throw new InvalidInputException(
                    "A review needs an outcome: " + java.util.Arrays.stream(ReviewOutcome.values())
                            .map(Enum::name).collect(java.util.stream.Collectors.joining(", ")) + ".");
        }
        if (comment != null && comment.length() > Triage.MAX_COMMENT_LENGTH) {
            throw new InvalidInputException(
                    "The comment is longer than " + Triage.MAX_COMMENT_LENGTH + " characters.");
        }

        IssueEntity issue = issues.findById(issueId)
                .orElseThrow(() -> new InvalidInputException("No such issue: " + issueId));

        TriageStatus current = TriageStatus.fromWireName(issue.getTriageStatus()).orElse(null);
        if (current != TriageStatus.NOT_AFFECTED && current != TriageStatus.WILL_NOT_FIX
                && current != TriageStatus.PENDING_APPROVAL) {
            // Reviewing an issue nobody excepted would put a row in the register for something
            // that is not an exception, which is exactly the noise the register exists to avoid.
            throw new InvalidInputException(
                    "Nothing to review: this issue carries no exception.");
        }
        if (outcome == ReviewOutcome.EXTENDED && newExpiry == null) {
            throw new InvalidInputException("Extending an exception needs the date it now runs to.");
        }

        Instant now = clock.instant();
        // **An extension runs forward, and not for ever.** A date in the past was accepted, and the
        // next maintenance tick expired the exception the reviewer had just extended — the review
        // recorded as "extended" while doing the opposite. A date past MySQL's year 9999 failed at
        // the write, as a 500. The ceiling is the one a triage's own review delay has.
        if (outcome == ReviewOutcome.EXTENDED) {
            if (!newExpiry.isAfter(now)) {
                throw new InvalidInputException("An extension runs to a date in the future.");
            }
            if (newExpiry.isAfter(Triage.latestReview(now))) {
                throw new InvalidInputException(
                        "An extension runs at most " + Triage.MAX_REVIEW_DAYS + " days from today.");
            }
        }
        String from = issue.getTriageStatus();
        String to = from;

        switch (outcome) {
            case CONFIRMED -> { }
            case EXTENDED -> issue.setTriageExpiresAt(newExpiry);
            case REVOKED -> {
                to = TriageStatus.UNDER_REVIEW.wireName();
                issue.setTriageStatus(to);
                // Cleared rather than left: an expiry surviving a revocation would bring the
                // withdrawn exception back through `expireStale` as though it had merely lapsed.
                issue.setTriageExpiresAt(null);
                // And a revoked request asks for nothing any more.
                issue.setTriageRequestedStatus(null);
            }
        }

        events.save(event(
                issue,
                from,
                to,
                issue.getTriageJustification(),
                comment,
                actor,
                REVIEW,
                now,
                issue.getTriageExpiresAt()));

        return written(() -> issues.saveAndFlush(issue));
    }

    /**
     * A person's decision written now, in its own words if the issue changed since it was read.
     *
     * <p><b>Flushed here, not at the commit</b>, so the refusal is raised where it can be named: the
     * issue's revision (V89) refuses a write naming one a scan or another decision has since replaced,
     * and at the commit the same refusal reached the caller as a 500. The decision rolls back whole, its
     * history row with it.
     */
    private static <T> T written(java.util.function.Supplier<T> write) {
        try {
            return write.get();
        } catch (OptimisticLockingFailureException changed) {
            throw new IssueChangedMeanwhileException();
        }
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
            // A request that waited past its own review date lapses with it: the issue is back under
            // review and asks nobody for anything.
            issue.setTriageRequestedStatus(null);
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
