package com.asmolabs.vectispire.core.tickets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/**
 * The ticket sweep against a database.
 *
 * <p>The tracker is the one thing faked — a real one would make this a network test. Everything
 * else is real, because the claims worth checking are about the query: that it excludes what is
 * dismissed, that it excludes what already has a ticket, and that it serves the most severe
 * first. The last is the one a fake cannot show at all, since the ordering is a {@code case}
 * expression in SQL rather than a comparator.
 */
@DisplayName("opening tickets, against a database")
class TicketSweepDatabaseTest extends VectispireContextTest {

    @Autowired
    private TicketSweepService sweep;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private GitRepositoryRepository repositories;

    @MockitoBean
    private TicketService tickets;

    private long repositoryId;

    @BeforeEach
    void seed() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/tickets.git");
        repository.setBranch("main");
        repositoryId = repositories.save(repository).getId();

        when(tickets.isEnabled()).thenReturn(true);
        when(tickets.createForIssue(any(), anyString()))
                .thenReturn(Optional.of(new TicketService.Ticket("#1", "https://tracker.invalid/1")));
    }

    @Test
    @DisplayName("the reference is stored, so the next pass leaves the issue alone")
    void theReferenceDeduplicates() {
        long id = issue(Severity.CRITICAL, TriageStatus.UNDER_REVIEW);

        assertThat(sweep.sweep(20)).isEqualTo(1);
        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isEqualTo("#1");

        // Idempotent by construction: the stored reference *is* the deduplication key, which is
        // why this needs no outbox.
        assertThat(sweep.sweep(20)).isZero();
    }

    @Test
    @DisplayName("a dismissed issue is not a candidate")
    void dismissedIssuesAreExcluded() {
        issue(Severity.CRITICAL, TriageStatus.NOT_AFFECTED);
        issue(Severity.CRITICAL, TriageStatus.FIXED);

        // The two judgments that say "nothing to plan". Everything else stays a candidate,
        // `under_review` included — an issue nobody has looked at is exactly the one that needs
        // to exist somewhere other than a dashboard.
        assertThat(sweep.sweep(20)).isZero();
    }

    @Test
    @DisplayName("the ceiling serves the most severe first, not the oldest")
    void theCeilingServesWhatMatters() {
        issue(Severity.LOW, TriageStatus.UNDER_REVIEW);
        issue(Severity.MEDIUM, TriageStatus.UNDER_REVIEW);
        long critical = issue(Severity.CRITICAL, TriageStatus.UNDER_REVIEW);

        // One ticket allowed. A mature backlog ordered by identifier would spend it on the
        // harmless finding inserted first, and yesterday's critical would wait days.
        assertThat(sweep.sweep(1)).isEqualTo(1);
        assertThat(issues.findById(critical).orElseThrow().getTicketRef()).isEqualTo("#1");
    }

    @Test
    @DisplayName("an issue below the gate's bar gets no ticket and no marker")
    void aHarmlessIssueIsLeftUnmarked() {
        long low = issue(Severity.LOW, TriageStatus.UNDER_REVIEW);

        assertThat(sweep.sweep(20)).isZero();
        // No marker either: the policy can be tightened tomorrow, and the issue has to become a
        // candidate again then.
        assertThat(issues.findById(low).orElseThrow().getTicketRef()).isNull();
    }

    @Test
    void doesNothingWhenTicketingIsOff() {
        when(tickets.isEnabled()).thenReturn(false);
        issue(Severity.CRITICAL, TriageStatus.UNDER_REVIEW);

        assertThat(sweep.sweep(20)).isZero();
    }

    private long issue(Severity severity, TriageStatus triage) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint("f-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-" + System.nanoTime());
        issue.setSeverity(severity.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(triage.wireName());
        issue.setFixVersions("3.5.2");
        issue.setFirstSeenAt(Instant.now());
        issue.setLastSeenAt(Instant.now());
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }

    @Test
    @DisplayName("two sweeps at once open one ticket: the issue is claimed before the tracker is asked")
    void twoOverlappingSweepsOpenOneTicket() throws Exception {
        long id = issue(Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
        java.util.concurrent.CountDownLatch asking = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        when(tickets.createForIssue(any(), anyString())).thenAnswer(call -> {
            asking.countDown();
            release.await(30, java.util.concurrent.TimeUnit.SECONDS);
            return Optional.of(new TicketService.Ticket("#1", "https://tracker.invalid/1"));
        });

        // The first pass is asking the tracker; the second runs whole meanwhile, as another instance's would.
        var first = java.util.concurrent.CompletableFuture.supplyAsync(() -> sweep.sweep(20));
        assertThat(asking.await(30, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
        int second = sweep.sweep(20);
        release.countDown();

        assertThat(second).isZero();
        assertThat(first.get(30, java.util.concurrent.TimeUnit.SECONDS)).isEqualTo(1);
        org.mockito.Mockito.verify(tickets, org.mockito.Mockito.times(1)).createForIssue(any(), anyString());
        IssueEntity stored = issues.findById(id).orElseThrow();
        assertThat(stored.getTicketRef()).isEqualTo("#1");
        assertThat(stored.getTicketClaimedBy()).as("attaching clears the claim").isNull();
    }

    @Test
    @DisplayName("an issue another instance is asking a ticket for is left to it, until its claim lapses")
    void anotherInstancesClaimIsHonouredUntilItLapses() {
        long id = issue(Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
        java.time.Instant now = java.time.Instant.now();
        assertThat(issues.claimTicket(id, "another-instance", now.plus(java.time.Duration.ofMinutes(5)), now)).isOne();

        assertThat(sweep.sweep(20)).isZero();
        org.mockito.Mockito.verify(tickets, org.mockito.Mockito.never()).createForIssue(any(), anyString());

        // That instance died between its claim and the reference: once the claim lapses, the issue is taken over.
        issues.releaseTicketClaim(id, "another-instance");
        assertThat(issues.claimTicket(id, "another-instance", now.minusSeconds(1), now.minusSeconds(60))).isOne();
        assertThat(sweep.sweep(20)).isEqualTo(1);
        assertThat(issues.findById(id).orElseThrow().getTicketRef()).isEqualTo("#1");
    }

    @Test
    @DisplayName("a tracker that answers nothing gives the claim up, so the next pass tries again")
    void aRefusalReleasesTheClaim() {
        long id = issue(Severity.CRITICAL, TriageStatus.UNDER_REVIEW);
        when(tickets.createForIssue(any(), anyString())).thenReturn(Optional.empty());

        assertThat(sweep.sweep(20)).isZero();
        IssueEntity stored = issues.findById(id).orElseThrow();
        assertThat(stored.getTicketRef()).isNull();
        assertThat(stored.getTicketClaimedBy()).isNull();
        assertThat(stored.getTicketClaimUntil()).isNull();
    }
}
