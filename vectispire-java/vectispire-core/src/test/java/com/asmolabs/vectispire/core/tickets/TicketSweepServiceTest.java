package com.asmolabs.vectispire.core.tickets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.tickets.TicketProvider;
import com.asmolabs.vectispire.common.domain.tickets.TrackerState;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicyRepository;
import com.asmolabs.vectispire.core.gate.persistence.GatePolicyEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

@DisplayName("opening tickets for what would fail a build")
class TicketSweepServiceTest {

    private IssueRepository issues;
    private GatePolicyRepository policies;
    private TicketService tickets;
    private AuditLogService audit;
    private TicketSweepService sweep;

    @BeforeEach
    void wire() {
        issues = mock(IssueRepository.class);
        policies = mock(GatePolicyRepository.class);
        tickets = mock(TicketService.class);
        audit = mock(AuditLogService.class);
        TargetNaming naming = mock(TargetNaming.class);
        when(naming.all()).thenReturn(new TargetNaming.Names(Map.of(), Map.of()));

        sweep = new TicketSweepService(
                new com.asmolabs.vectispire.core.issues.IssueCatalog(issues),
                new com.asmolabs.vectispire.core.gate.ActiveGatePolicies(policies), naming, tickets, audit,
                java.time.Clock.systemUTC());
        // The claim this instance takes before asking the tracker (V95): won, as one instance alone wins it.
        when(issues.claimTicket(anyLong(), anyString(), any(), any())).thenReturn(1);

        when(tickets.isEnabled()).thenReturn(true);
        when(policies.findByIsActiveTrue()).thenReturn(List.of());
        when(issues.findActionableWithoutTicket(anyString(), any(), any())).thenReturn(List.of());
        when(tickets.createForIssue(any(), anyString()))
                .thenReturn(Optional.of(new TicketService.Ticket("#12", "https://gitlab.example/issues/12")));
    }

    @Test
    @DisplayName("an issue above the bar gets a ticket, and the reference is stored")
    void opensATicketAndRecordsIt() {
        candidates(issue(Severity.CRITICAL));

        assertThat(sweep.sweep(20)).isEqualTo(1);
        verify(issues).attachTicket(1L, "#12", "https://gitlab.example/issues/12");
        verify(audit).record(any());
    }

    @Test
    @DisplayName("a ticket opened for an issue a person attached one to meanwhile is said to be unrecorded, not dropped")
    void aTicketTheIssueNoLongerTakes() {
        candidates(issue(Severity.CRITICAL));
        // The conditional statement wrote nothing: a reference was attached while the tracker answered.
        when(issues.attachTicket(anyLong(), anyString(), anyString())).thenReturn(0);

        assertThat(sweep.sweep(20)).isEqualTo(1);
        org.mockito.ArgumentCaptor<AuditLogService.Record> entry = org.mockito.ArgumentCaptor.forClass(AuditLogService.Record.class);
        verify(audit).record(entry.capture());
        assertThat(entry.getValue().description())
                .contains("Ticket #12 opened")
                .contains("not recorded on the issue");
    }

    @Test
    @DisplayName("a ticket recorded on its issue says nothing of the kind")
    void aTicketRecorded() {
        candidates(issue(Severity.CRITICAL));
        when(issues.attachTicket(anyLong(), anyString(), anyString())).thenReturn(1);

        sweep.sweep(20);
        org.mockito.ArgumentCaptor<AuditLogService.Record> entry = org.mockito.ArgumentCaptor.forClass(AuditLogService.Record.class);
        verify(audit).record(entry.capture());
        assertThat(entry.getValue().description()).doesNotContain("not recorded");
    }

    @Test
    @DisplayName("an issue below the bar gets no ticket and no marker")
    void leavesAHarmlessIssueAlone() {
        candidates(issue(Severity.LOW));

        assertThat(sweep.sweep(20)).isZero();
        // No marker either: the policy can be tightened tomorrow, and the issue has to become a
        // candidate again then.
        verify(issues, never()).attachTicket(anyLong(), anyString(), anyString());
    }

    @Test
    @DisplayName("a target's own policy replaces the global one")
    void aTargetPolicyOverridesTheGlobalOne() {
        candidates(issue(Severity.MEDIUM));
        when(policies.findByIsActiveTrue()).thenReturn(List.of(
                policy("global", null, Severity.CRITICAL),
                policy("repository", 5L, Severity.MEDIUM)));

        assertThat(sweep.sweep(20)).isEqualTo(1);
    }

    @Test
    @DisplayName("a tracker outage leaves the issue without a reference, for the next pass")
    void aFailedCreationIsRetriedLater() {
        candidates(issue(Severity.CRITICAL));
        when(tickets.createForIssue(any(), anyString())).thenReturn(Optional.empty());

        assertThat(sweep.sweep(20)).isZero();
        verify(issues, never()).attachTicket(anyLong(), anyString(), anyString());
    }

    @Test
    void doesNothingWhenTicketingIsOff() {
        when(tickets.isEnabled()).thenReturn(false);

        assertThat(sweep.sweep(20)).isZero();
        verify(issues, never()).findActionableWithoutTicket(anyString(), any(), any());
    }

    @Test
    @DisplayName("a suspended tracker opens and closes nothing, and the pass says so once, then once when it resumes")
    void aSuspendedTrackerIsSaidOnce() {
        Integration jira = Integration.of(TicketProvider.JIRA);
        candidates(issue(Severity.CRITICAL));
        when(tickets.standing()).thenReturn(Optional.of(new TicketService.Standing(jira, TrackerState.SUSPENDED)));
        when(tickets.isEnabled()).thenReturn(false);

        List<String> said = logged(() -> {
            assertThat(sweep.sweep(20)).isZero();
            assertThat(sweep.sweep(20)).isZero();
            assertThat(sweep.sweep(20)).isZero();
        });

        verify(issues, never()).findActionableWithoutTicket(anyString(), any(), any());
        verify(issues, never()).findResolvedWithOpenTicket(any());
        verify(tickets, never()).createForIssue(any(), anyString());
        verify(tickets, never()).closeTicket(anyString(), anyString());
        assertThat(said).as("once over three hourly passes, not once an hour").singleElement()
                .satisfies(line -> assertThat(line).contains("tracker.jira integration is disabled")
                        .contains("token, its settings and the issues' tickets are kept"));

        when(tickets.standing()).thenReturn(Optional.of(new TicketService.Standing(jira, TrackerState.ACTIVE)));
        when(tickets.isEnabled()).thenReturn(true);
        List<String> resumed = logged(() -> {
            assertThat(sweep.sweep(20)).as("re-enabled: the issue gets its ticket").isEqualTo(1);
            sweep.sweep(20);
        });
        assertThat(resumed).filteredOn(line -> line.contains("enabled again")).singleElement()
                .satisfies(line -> assertThat(line).contains("tracker.jira"));
        assertThat(resumed).noneMatch(line -> line.contains("is disabled"));
    }

    /** The sweep's log lines while {@code pass} runs. */
    private static List<String> logged(Runnable pass) {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        Logger logger = (Logger) LoggerFactory.getLogger(TicketSweepService.class);
        appender.start();
        logger.addAppender(appender);
        try {
            pass.run();
        } finally {
            logger.detachAppender(appender);
        }
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Test
    @DisplayName("an issue attached to no target falls back to the global policy")
    void anOrphanIssueUsesTheGlobalPolicy() {
        IssueEntity orphan = issue(Severity.CRITICAL);
        orphan.setRepoId(null);
        candidates(orphan);
        when(policies.findByIsActiveTrue()).thenReturn(List.of(policy("global", null, Severity.CRITICAL)));

        assertThat(sweep.sweep(20)).isEqualTo(1);
    }

    private void candidates(IssueEntity... rows) {
        when(issues.findActionableWithoutTicket(anyString(), any(), any())).thenReturn(List.of(rows));
    }

    private static IssueEntity issue(Severity severity) {
        IssueEntity issue = new IssueEntity();
        issue.setId(1L);
        issue.setRepoId(5L);
        issue.setState(IssueState.OPEN.wireName());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-1");
        issue.setSeverity(severity.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFixVersions("3.5.2");
        return issue;
    }

    private static GatePolicyEntity policy(String kind, Long targetId, Severity failOn) {
        GatePolicyEntity policy = new GatePolicyEntity();
        policy.setTargetKind(kind);
        policy.setTargetId(targetId);
        policy.setVersion(1);
        policy.setIsActive(true);
        policy.setFailOnSeverity(failOn.wireName());
        policy.setFailOnKev(true);
        return policy;
    }
}
