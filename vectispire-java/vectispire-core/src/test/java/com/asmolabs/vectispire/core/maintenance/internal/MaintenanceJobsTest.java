package com.asmolabs.vectispire.core.maintenance.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.notifications.OutboxRetry;
import com.asmolabs.vectispire.core.access.SessionCleanupService;
import com.asmolabs.vectispire.core.access.internal.SessionCleanupTask;
import com.asmolabs.vectispire.core.compliance.ComplianceHistoryService;
import com.asmolabs.vectispire.core.compliance.internal.ComplianceHistoryTask;
import com.asmolabs.vectispire.core.inventory.InventoryBackfill;
import com.asmolabs.vectispire.core.inventory.internal.InventoryBackfillTask;
import com.asmolabs.vectispire.core.issues.IssueTriageService;
import com.asmolabs.vectispire.core.issues.internal.TriageExpiryTask;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.outbox.internal.NotificationRelayTask;
import com.asmolabs.vectispire.core.outbox.internal.SentMessagesTask;
import com.asmolabs.vectispire.core.posture.PostureDigestService;
import com.asmolabs.vectispire.core.posture.internal.WeeklyDigestTask;
import com.asmolabs.vectispire.core.scanning.RetentionService;
import com.asmolabs.vectispire.core.scanning.SchedulerService;
import com.asmolabs.vectispire.core.scanning.internal.ScanRetentionTask;
import com.asmolabs.vectispire.core.scanning.internal.SchedulingTickTask;
import com.asmolabs.vectispire.core.targets.TargetDeletionService;
import com.asmolabs.vectispire.core.targets.internal.OrphanedTargetRowsTask;
import com.asmolabs.vectispire.core.tickets.TicketSweepService;
import com.asmolabs.vectispire.core.tickets.internal.TicketSweepTask;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

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
 *
 * <p><b>Two halves since the tick stopped naming the services</b> (decision 0029). Each module
 * contributes a {@link MaintenanceTask}; this suite runs the tick over {@link #COMPOSITION} — the
 * tasks, built on mocks — and asserts every call, while {@code MaintenanceCompositionTest} asserts
 * that the running application contributes exactly those tasks, in that order. Either half alone
 * would prove less than its name: the first a list written by hand, the second beans that might call
 * nothing.
 */
@DisplayName("the periodic tick")
class MaintenanceJobsTest {

    /** Every task the application contributes, in the order it runs them. */
    static final List<Class<? extends MaintenanceTask>> COMPOSITION = List.of(
            NotificationRelayTask.class,
            SchedulingTickTask.class,
            ScanRetentionTask.class,
            SentMessagesTask.class,
            TicketSweepTask.class,
            InventoryBackfillTask.class,
            TriageExpiryTask.class,
            WeeklyDigestTask.class,
            ComplianceHistoryTask.class,
            SessionCleanupTask.class,
            OrphanedTargetRowsTask.class);

    private RetentionService retention;
    private OutboxService outbox;
    private TicketSweepService tickets;
    private SessionCleanupService sessions;
    private InventoryBackfill backfill;
    private SchedulerService scheduler;
    private IssueTriageService triage;
    private PostureDigestService digest;
    private TargetDeletionService targetDeletion;
    private ComplianceHistoryService complianceHistory;
    private List<MaintenanceTask> tasks;
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
        digest = mock(PostureDigestService.class);
        targetDeletion = mock(TargetDeletionService.class);
        complianceHistory = mock(ComplianceHistoryService.class);

        when(sessions.prune()).thenReturn(new SessionCleanupService.CleanupResult(0, 0, 0, 0));
        when(triage.expireStale()).thenReturn(List.of());

        tasks = List.of(
                new NotificationRelayTask(outbox),
                new SchedulingTickTask(scheduler),
                new ScanRetentionTask(retention),
                new SentMessagesTask(outbox),
                new TicketSweepTask(tickets),
                new InventoryBackfillTask(backfill),
                new TriageExpiryTask(triage),
                new WeeklyDigestTask(digest),
                new ComplianceHistoryTask(complianceHistory),
                new SessionCleanupTask(sessions),
                new OrphanedTargetRowsTask(targetDeletion));
        jobs = new MaintenanceJobs(tasks);
    }

    @Test
    @DisplayName("the tasks built here are the composition the application is held to")
    void theseAreTheComposition() {
        // Without this, a task added to COMPOSITION and not built above would leave every assertion
        // below green while the new task was never run.
        assertThat(tasks).map(Object::getClass).containsExactlyElementsOf(COMPOSITION);
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
    @DisplayName("and everything else the turn is responsible for, in its order")
    void theWholeTurnRuns() {
        jobs.hourlyMaintenance();

        // Listed rather than counted: a job added to the tick and forgotten here would leave this
        // suite green while proving one thing fewer, which is how a composition test comes to
        // cover less than its name says. In order, because two positions matter: the decisions
        // expire before the digest and the compliance capture read the backlog, and the orphaned
        // rows go last.
        InOrder turn = inOrder(retention, outbox, tickets, backfill, triage, digest, complianceHistory, sessions,
                targetDeletion);
        turn.verify(retention).prune();
        turn.verify(outbox).pruneSent();
        turn.verify(tickets).sweep();
        turn.verify(backfill).runOnce();
        turn.verify(triage).expireStale();
        turn.verify(digest).runOnce();
        turn.verify(complianceHistory).capture();
        turn.verify(sessions).prune();
        turn.verify(targetDeletion).purgeOrphanedTargetData();
    }

    @Test
    @DisplayName("the hourly turn neither relays nor schedules")
    void theHourlyTurnIsOnlyTheHourlyTasks() {
        jobs.hourlyMaintenance();

        verify(outbox, never()).relay(anyInt());
        verify(scheduler, never()).runOnce();
    }

    @Test
    @DisplayName("a job that throws ends its turn, and the next turn runs")
    void aFailureIsContainedButTheTurnGoesOn() {
        when(retention.prune()).thenThrow(new IllegalStateException("disk full"));

        // Swallowed by design — housekeeping must not bring down the process serving requests.
        // What matters is the consequence nobody would notice otherwise: the guard resets, so the
        // next turn runs, and one failing job does not silence the tick for ever. The jobs after
        // the failing one wait for that next turn, as they did when the turn was a single method.
        jobs.hourlyMaintenance();
        jobs.hourlyMaintenance();

        verify(retention, times(2)).prune();
        verify(outbox, never()).pruneSent();
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
        verify(retention, never()).prune();
    }

    @Test
    @DisplayName("the relay asks for the batch size the backoff policy names")
    void theRelayBatchIsThePolicys() {
        jobs.relayNotifications();

        // Not a number chosen here: the policy owns it, and two answers to "how many per pass"
        // would drift.
        verify(outbox).relay(OutboxRetry.MAX_PER_PASS);
    }

    @Test
    @DisplayName("the hourly turn offers to send the weekly report")
    void theWeeklyReportIsOffered() {
        jobs.hourlyMaintenance();

        // A weekly report has no queue — it is derived from the database, so a failed send is
        // recomputed next turn — which makes this call the only thing that makes the feature
        // exist. Exactly the shape `expireStale` had while its javadoc claimed this tick ran it.
        verify(digest).runOnce();
    }
}
