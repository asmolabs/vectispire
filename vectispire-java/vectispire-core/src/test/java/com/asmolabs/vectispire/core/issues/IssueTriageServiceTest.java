package com.asmolabs.vectispire.core.issues;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.InvalidTriageException;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.Period;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("recording and expiring a triage decision")
class IssueTriageServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T09:00:00Z");

    private IssueRepository issues;
    private com.asmolabs.vectispire.core.issues.persistence.TriageEventRepository events;
    private IssueTriageService service;

    @BeforeEach
    void wire() {
        issues = mock(IssueRepository.class);
        events = mock(com.asmolabs.vectispire.core.issues.persistence.TriageEventRepository.class);
        service = new IssueTriageService(issues, events, Clock.fixed(NOW, ZoneOffset.UTC));
        when(issues.save(any())).thenAnswer(call -> call.getArgument(0));
        when(issues.saveAll(any())).thenAnswer(call -> call.getArgument(0));
        when(issues.saveAndFlush(any())).thenAnswer(call -> call.getArgument(0));
        when(issues.saveAllAndFlush(any())).thenAnswer(call -> call.getArgument(0));
        when(events.save(any())).thenAnswer(call -> call.getArgument(0));
    }

    /** The single event this call recorded. */
    private com.asmolabs.vectispire.core.issues.persistence.TriageEventEntity recorded() {
        var captor = org.mockito.ArgumentCaptor.forClass(
                com.asmolabs.vectispire.core.issues.persistence.TriageEventEntity.class);
        org.mockito.Mockito.verify(events).save(captor.capture());
        return captor.getValue();
    }

    @Test
    void writesTheDecisionOntoTheIssue() {
        when(issues.findById(1L)).thenReturn(Optional.of(issue(TriageStatus.UNDER_REVIEW, null)));

        IssueEntity triaged = service.triage(1L, new Triage.Request(
                TriageStatus.NOT_AFFECTED, "alice", VexJustification.VULNERABLE_CODE_NOT_PRESENT,
                "The affected module is not compiled in.", Period.ofDays(90)));

        assertThat(triaged.getTriageStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
        assertThat(triaged.getTriagedBy()).isEqualTo("alice");
        assertThat(triaged.getTriagedAt()).isEqualTo(NOW);
        assertThat(triaged.getTriageExpiresAt()).isEqualTo(NOW.plus(Period.ofDays(90)));
    }

    @Test
    @DisplayName("records the transition, both ends of it, against the version in force")
    void recordsTheTransition() {
        // The left half is the whole point. Capturing the status after the assignment would
        // record every decision as going from its own outcome to itself, and a history of
        // "accepted -> accepted" proves nothing about a change of position.
        IssueEntity issue = issue(TriageStatus.UNDER_REVIEW, null);
        issue.setLastSeenScanId(17L);
        when(issues.findById(1L)).thenReturn(Optional.of(issue));

        service.triage(1L, new Triage.Request(
                TriageStatus.NOT_AFFECTED, "alice", VexJustification.VULNERABLE_CODE_NOT_PRESENT,
                "The affected module is not compiled in.", Period.ofDays(90)));

        var event = recorded();
        assertThat(event.getFromStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
        assertThat(event.getToStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
        assertThat(event.getActor()).isEqualTo("alice");
        assertThat(event.getOrigin()).isEqualTo("manual");
        assertThat(event.getOccurredAt()).isEqualTo(NOW);
        assertThat(event.getScanId())
                .describedAs("the scan in force, so the trail can say which version was accepted")
                .isEqualTo(17L);
    }

    @Test
    @DisplayName("a non-approver requesting not_affected transitions the issue to pending_approval")
    void nonApproverCreatesPendingApprovalRequest() {
        IssueEntity issue = issue(TriageStatus.UNDER_REVIEW, null);
        when(issues.findById(1L)).thenReturn(Optional.of(issue));

        IssueEntity triaged = service.triage(1L, new Triage.Request(
                TriageStatus.NOT_AFFECTED, "bob_dev", VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
                "Mitigation in gateway.", Period.ofDays(30)), false);

        assertThat(triaged.getTriageStatus()).isEqualTo(TriageStatus.PENDING_APPROVAL.wireName());
        assertThat(triaged.getTriagedBy()).isEqualTo("bob_dev");

        var event = recorded();
        assertThat(event.getFromStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
        assertThat(event.getToStatus()).isEqualTo(TriageStatus.PENDING_APPROVAL.wireName());
        assertThat(event.getActor()).isEqualTo("bob_dev");
        assertThat(event.getOrigin()).isEqualTo("manual");
    }

    @Test
    @DisplayName("an approver settling a pending_approval issue records the origin as approval")
    void approverSettlesPendingApproval() {
        IssueEntity issue = issue(TriageStatus.PENDING_APPROVAL, null);
        when(issues.findById(1L)).thenReturn(Optional.of(issue));

        IssueEntity approved = service.triage(1L, new Triage.Request(
                TriageStatus.NOT_AFFECTED, "carol_champion", VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
                "Reviewed and confirmed.", Period.ofDays(30)), true);

        assertThat(approved.getTriageStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
        assertThat(approved.getTriagedBy()).isEqualTo("carol_champion");

        var event = recorded();
        assertThat(event.getFromStatus()).isEqualTo(TriageStatus.PENDING_APPROVAL.wireName());
        assertThat(event.getToStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
        assertThat(event.getActor()).isEqualTo("carol_champion");
        assertThat(event.getOrigin()).isEqualTo("approval");
    }

    @Test
    @DisplayName("an expiry is recorded as a decision nobody took")
    void expiryIsRecordedWithoutAnActor() {
        IssueEntity dismissed = issue(TriageStatus.NOT_AFFECTED, NOW.minusSeconds(1));
        dismissed.setTriagedBy("alice");
        when(issues.findWithExpiredTriage(NOW)).thenReturn(List.of(dismissed));

        service.expireStale();

        var event = recorded();
        assertThat(event.getFromStatus()).isEqualTo(TriageStatus.NOT_AFFECTED.wireName());
        assertThat(event.getToStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
        assertThat(event.getOrigin()).isEqualTo("expiry");
        // Alice decided the acceptance; she did not decide that it lapsed. Naming her here would
        // attribute an action to somebody who did not take it, in a document meant as evidence.
        assertThat(event.getActor()).isNull();
    }

    @Test
    @DisplayName("nothing to expire records nothing, or the history fills with non-events")
    void nothingToExpireRecordsNothing() {
        IssueEntity already = issue(TriageStatus.UNDER_REVIEW, NOW.minusSeconds(1));
        when(issues.findWithExpiredTriage(NOW)).thenReturn(List.of(already));

        service.expireStale();

        org.mockito.Mockito.verify(events, org.mockito.Mockito.never()).save(any());
    }

    @Test
    @DisplayName("a malformed request is refused before the issue is even loaded")
    void validationPrecedesTheQuery() {
        assertThatThrownBy(() -> service.triage(1L, new Triage.Request(null, "alice", null, null, null)))
                .isInstanceOf(InvalidTriageException.class);

        org.mockito.Mockito.verify(issues, org.mockito.Mockito.never()).findById(any());
    }

    @Test
    void refusesAnIssueThatIsNotThere() {
        when(issues.findById(9L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.triage(9L, new Triage.Request(
                        TriageStatus.FIXED, "alice", null, null, null)))
                .isInstanceOf(InvalidTriageException.class);
    }

    @Test
    @DisplayName("an expired dismissal returns to review, keeping who decided and why")
    void expiryKeepsTheEvidence() {
        IssueEntity dismissed = issue(TriageStatus.NOT_AFFECTED, NOW.minusSeconds(1));
        dismissed.setTriagedBy("alice");
        dismissed.setTriageComment("Not compiled in.");
        when(issues.findWithExpiredTriage(NOW)).thenReturn(List.of(dismissed));

        assertThat(service.expireStale()).containsExactly(1L);

        assertThat(dismissed.getTriageStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
        assertThat(dismissed.getTriageExpiresAt()).isNull();
        // Erasing the reason turns a scheduled review into an investigation from scratch, which
        // is how a review date becomes a field people stop filling in.
        assertThat(dismissed.getTriagedBy()).isEqualTo("alice");
        assertThat(dismissed.getTriageComment()).isEqualTo("Not compiled in.");
    }

    @Test
    @DisplayName("a row already under review is left alone rather than re-stamped")
    void nothingToExpireIsNotRewritten() {
        IssueEntity already = issue(TriageStatus.UNDER_REVIEW, NOW.minusSeconds(1));
        already.setTriagedAt(NOW.minusSeconds(3600));
        when(issues.findWithExpiredTriage(NOW)).thenReturn(List.of(already));

        assertThat(service.expireStale()).isEmpty();
        assertThat(already.getTriagedAt()).isEqualTo(NOW.minusSeconds(3600));
    }

    @Test
    @DisplayName("a queued acceptance keeps the status it asked for, and its review date, on the issue and in the history")
    void aQueuedDecisionKeepsWhatItAskedFor() {
        IssueEntity issue = issue(TriageStatus.UNDER_REVIEW, null);
        when(issues.findById(1L)).thenReturn(Optional.of(issue));

        IssueEntity queued = service.triage(1L, new Triage.Request(
                TriageStatus.WILL_NOT_FIX, "bob_dev", null, "Legacy module, retired in Q3.", Period.ofDays(90)), false);

        assertThat(queued.getTriageStatus()).isEqualTo(TriageStatus.PENDING_APPROVAL.wireName());
        // Dropped here, the approver saw `pending_approval` and chose — a "Won't Fix" granted as a
        // clearance the signed VEX then stated as "not exposed".
        assertThat(queued.getTriageRequestedStatus()).isEqualTo(TriageStatus.WILL_NOT_FIX.wireName());
        assertThat(queued.getTriageExpiresAt())
                .describedAs("the review date the requester proposed, which the approval dialog offers again")
                .isEqualTo(NOW.plus(Period.ofDays(90)));

        var event = recorded();
        assertThat(event.getToStatus()).isEqualTo(TriageStatus.PENDING_APPROVAL.wireName());
        assertThat(event.getRequestedStatus()).isEqualTo(TriageStatus.WILL_NOT_FIX.wireName());
        assertThat(event.getExpiresAt()).isEqualTo(NOW.plus(Period.ofDays(90)));
    }

    @Test
    @DisplayName("a request for an accepted risk cannot be granted as not affected")
    void anApprovalCannotGrantAnotherStatus() {
        IssueEntity issue = pendingRequestFor(TriageStatus.WILL_NOT_FIX);
        when(issues.findById(1L)).thenReturn(Optional.of(issue));

        assertThatThrownBy(() -> service.triage(1L, new Triage.Request(
                        TriageStatus.NOT_AFFECTED, "carol_champion", VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
                        "Looks mitigated to me.", Period.ofDays(30)), true))
                .isInstanceOf(TriageApprovalDiffersException.class)
                .hasMessageContaining("will_not_fix")
                .satisfies(refusal -> assertThat(((TriageApprovalDiffersException) refusal).members())
                        .containsEntry("requestedStatus", "will_not_fix"));

        assertThat(issue.getTriageStatus()).isEqualTo(TriageStatus.PENDING_APPROVAL.wireName());
        assertThat(issue.getTriageRequestedStatus()).isEqualTo(TriageStatus.WILL_NOT_FIX.wireName());
        org.mockito.Mockito.verify(events, org.mockito.Mockito.never()).save(any());
    }

    @Test
    @DisplayName("the same refusal on a bulk decision that would grant one of its requests as something else")
    void aBulkApprovalCannotGrantAnotherStatus() {
        IssueEntity asked = pendingRequestFor(TriageStatus.FIXED);
        when(issues.findAllById(List.of(1L))).thenReturn(List.of(asked));

        assertThatThrownBy(() -> service.triageAll(List.of(1L), new Triage.Request(
                        TriageStatus.WILL_NOT_FIX, "carol_champion", null, null, Period.ofDays(30)), true))
                .isInstanceOf(TriageApprovalDiffersException.class);
    }

    @Test
    @DisplayName("granted as asked, the status applies, the request is cleared, and the history says approval")
    void anApprovalGrantsWhatWasAsked() {
        IssueEntity issue = pendingRequestFor(TriageStatus.WILL_NOT_FIX);
        when(issues.findById(1L)).thenReturn(Optional.of(issue));

        IssueEntity granted = service.triage(1L, new Triage.Request(
                TriageStatus.WILL_NOT_FIX, "carol_champion", null, "Accepted until the migration.", Period.ofDays(60)),
                true);

        assertThat(granted.getTriageStatus()).isEqualTo(TriageStatus.WILL_NOT_FIX.wireName());
        assertThat(granted.getTriageRequestedStatus()).isNull();
        assertThat(granted.getTriageExpiresAt()).isEqualTo(NOW.plus(Period.ofDays(60)));
        var event = recorded();
        assertThat(event.getOrigin()).isEqualTo("approval");
        assertThat(event.getToStatus()).isEqualTo(TriageStatus.WILL_NOT_FIX.wireName());
        assertThat(event.getRequestedStatus()).isNull();
    }

    @Test
    @DisplayName("an approver who disagrees turns the request down, which clears it")
    void aRequestCanBeTurnedDown() {
        IssueEntity issue = pendingRequestFor(TriageStatus.WILL_NOT_FIX);
        when(issues.findById(1L)).thenReturn(Optional.of(issue));

        IssueEntity refused = service.triage(1L, new Triage.Request(
                TriageStatus.AFFECTED, "carol_champion", null, "Fix it.", null), true);

        assertThat(refused.getTriageStatus()).isEqualTo(TriageStatus.AFFECTED.wireName());
        assertThat(refused.getTriageRequestedStatus()).isNull();
        assertThat(recorded().getOrigin()).isEqualTo("manual");
    }

    @Test
    @DisplayName("a request that lapses at its review date asks for nothing any more")
    void aLapsedRequestIsCleared() {
        IssueEntity issue = pendingRequestFor(TriageStatus.WILL_NOT_FIX);
        issue.setTriageExpiresAt(NOW.minusSeconds(1));
        when(issues.findWithExpiredTriage(NOW)).thenReturn(List.of(issue));

        service.expireStale();

        assertThat(issue.getTriageStatus()).isEqualTo(TriageStatus.UNDER_REVIEW.wireName());
        assertThat(issue.getTriageRequestedStatus()).isNull();
    }

    private static IssueEntity pendingRequestFor(TriageStatus requested) {
        IssueEntity issue = issue(TriageStatus.PENDING_APPROVAL, NOW.plus(Period.ofDays(90)));
        issue.setTriageRequestedStatus(requested.wireName());
        issue.setTriagedBy("bob_dev");
        return issue;
    }

    private static IssueEntity issue(TriageStatus status, Instant expiresAt) {
        IssueEntity issue = new IssueEntity();
        issue.setId(1L);
        issue.setTriageStatus(status.wireName());
        issue.setTriageExpiresAt(expiresAt);
        return issue;
    }
}
