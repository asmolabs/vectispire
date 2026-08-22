package com.asmolabs.zanshin.core.services;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.common.domain.notifications.OutboxRetry;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What the periodic tick actually runs.
 *
 * <p><b>A suite about composition, which is unusual here and earned.</b> Every service below has
 * its own tests and they all passed while one of them was called by nobody:
 * {@code IssueTriageService.expireStale} was reachable only from its own suite, so an acceptance
 * recorded "for thirty days" kept its review date, exported it into SARIF, and never came back.
 * Its javadoc said it was called from this tick — and that sentence was the only place the claim
 * existed.
 *
 * <p>That is the defect this file exists to make impossible, and it is the same shape as the
 * built-in worker that claimed nothing because no bean supplied its runner: <b>a wiring that is
 * not exercised is not wired</b>, and no test of a service can see that its caller is missing.
 * Mocks are the right tool for once — what is being asserted is not what the jobs do, it is that
 * the tick calls them.
 */
@DisplayName("the periodic tick")
class MaintenanceJobsTest {

    private RetentionService retention;
    private OutboxService outbox;
    private TicketSweepService tickets;
    private SessionCleanupService sessions;
    private InventoryBackfill backfill;
    private SchedulerService scheduler;
    private IssueTriageService triage;
    private MaintenanceJobs jobs;

    @BeforeEach
    void wire() {
        retention = mock(RetentionService.class);
        outbox = mock(OutboxService.class);
        tickets = mock(TicketSweepService.class);
        sessions = mock(SessionCleanupService.class);
        backfill = mock(InventoryBackfill.class);
        scheduler = mock(SchedulerService.class);
        triage = mock(IssueTriageService.class);

        when(sessions.prune()).thenReturn(new SessionCleanupService.CleanupResult(0, 0));
        when(triage.expireStale()).thenReturn(List.of());

        jobs = new MaintenanceJobs(retention, outbox, tickets, sessions, backfill, scheduler, triage);
    }

    @Test
    @DisplayName("the hourly turn expires the triage decisions that reached their review date")
    void expiredTriagesAreBroughtBack() {
        jobs.hourlyMaintenance();

        // The assertion the codebase was missing. Without this call an accepted risk is permanent
        // — and permanent silently, because the date is stored, displayed in exports, and simply
        // never acted upon.
        verify(triage).expireStale();
    }

    @Test
    @DisplayName("and everything else the turn is responsible for")
    void theWholeTurnRuns() {
        jobs.hourlyMaintenance();

        // Listed rather than counted: a job added to the tick and forgotten here would leave this
        // suite green while proving one thing fewer, which is how a composition test comes to
        // cover less than its name says.
        verify(retention).prune();
        verify(outbox).pruneSent();
        verify(tickets).sweep();
        verify(backfill).runOnce();
        verify(sessions).prune();
    }

    @Test
    @DisplayName("a job that throws does not stop the ones after it")
    void aFailureIsContainedButTheTurnGoesOn() {
        when(retention.prune()).thenThrow(new IllegalStateException("disk full"));

        // Swallowed by design — housekeeping must not bring down the process serving requests.
        // What matters is the consequence nobody would notice otherwise: the guard resets, so the
        // next turn runs, and one failing job does not silence the tick for ever.
        jobs.hourlyMaintenance();
        jobs.hourlyMaintenance();

        verify(retention, org.mockito.Mockito.times(2)).prune();
    }

    @Test
    @DisplayName("the relay and the scheduler are their own turns, at their own intervals")
    void theOtherTwoJobs() {
        jobs.relayNotifications();
        jobs.scheduleDueScans();

        // Separate methods because they run at separate intervals: the relay every minute, the
        // scheduler every minute, the housekeeping hourly. A single method would have to run at
        // the shortest of the three.
        verify(outbox).relay(anyInt());
        verify(scheduler).runOnce();
    }

    @Test
    @DisplayName("the relay asks for the batch size the backoff policy names")
    void theRelayBatchIsThePolicys() {
        jobs.relayNotifications();

        // Not a number chosen here: the policy owns it, and two answers to "how many per pass"
        // would drift.
        verify(outbox).relay(OutboxRetry.MAX_PER_PASS);
    }
}
