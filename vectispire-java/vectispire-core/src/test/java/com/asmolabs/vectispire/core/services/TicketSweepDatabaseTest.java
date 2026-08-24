package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.core.ZanshinContextTest;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Issues;
import java.time.Instant;
import java.util.List;
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
class TicketSweepDatabaseTest extends ZanshinContextTest {

    @Autowired
    private TicketSweepService sweep;

    @Autowired
    private Issues issues;

    @Autowired
    private GitRepositories repositories;

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
}
