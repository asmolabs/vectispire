package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.issues.InvalidTriageException;
import com.asmolabs.zanshin.common.domain.issues.Triage;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.issues.VexJustification;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.Issues;
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

    private Issues issues;
    private com.asmolabs.zanshin.core.repositories.TriageEvents events;
    private IssueTriageService service;

    @BeforeEach
    void wire() {
        issues = mock(Issues.class);
        events = mock(com.asmolabs.zanshin.core.repositories.TriageEvents.class);
        service = new IssueTriageService(issues, events, Clock.fixed(NOW, ZoneOffset.UTC));
        when(issues.save(any())).thenAnswer(call -> call.getArgument(0));
        when(issues.saveAll(any())).thenAnswer(call -> call.getArgument(0));
        when(events.save(any())).thenAnswer(call -> call.getArgument(0));
    }

    /** The single event this call recorded. */
    private com.asmolabs.zanshin.core.persistence.TriageEventEntity recorded() {
        var captor = org.mockito.ArgumentCaptor.forClass(
                com.asmolabs.zanshin.core.persistence.TriageEventEntity.class);
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

    private static IssueEntity issue(TriageStatus status, Instant expiresAt) {
        IssueEntity issue = new IssueEntity();
        issue.setId(1L);
        issue.setTriageStatus(status.wireName());
        issue.setTriageExpiresAt(expiresAt);
        return issue;
    }
}
