package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.persistence.GatePolicyEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.GatePolicies;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("opening tickets for what would fail a build")
class TicketSweepServiceTest {

    private Issues issues;
    private GatePolicies policies;
    private TicketService tickets;
    private AuditLogService audit;
    private TicketSweepService sweep;

    @BeforeEach
    void wire() {
        issues = mock(Issues.class);
        policies = mock(GatePolicies.class);
        tickets = mock(TicketService.class);
        audit = mock(AuditLogService.class);
        TargetNaming naming = mock(TargetNaming.class);
        when(naming.all()).thenReturn(new TargetNaming.Names(Map.of(), Map.of()));

        sweep = new TicketSweepService(issues, policies, naming, tickets, audit);

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
