package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

@DisplayName("the periodic rescan")
class SchedulerServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-18T02:00:00Z");

    private GitRepositories repositories;
    private Containers containers;
    private Scans scans;
    private LeaderElection election;
    private SchedulerService scheduler;

    private final List<ScanEntity> queued = new ArrayList<>();

    @BeforeEach
    void wire() {
        repositories = mock(GitRepositories.class);
        containers = mock(Containers.class);
        scans = mock(Scans.class);
        election = mock(LeaderElection.class);

        PlatformTransactionManager manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenReturn(new SimpleTransactionStatus());

        scheduler = new SchedulerService(
                repositories, containers, scans, election, new TransactionTemplate(manager),
                Clock.fixed(NOW, ZoneOffset.UTC));

        queued.clear();
        when(election.acquire(anyString(), anyString(), any())).thenReturn(true);
        when(repositories.findAll()).thenReturn(List.of());
        when(containers.findAll()).thenReturn(List.of());
        when(scans.save(any())).thenAnswer(call -> {
            queued.add(call.getArgument(0));
            return call.getArgument(0);
        });
    }

    @Test
    @DisplayName("a due repository is queued and stamped")
    void queuesADueRepository() {
        when(repositories.findAll()).thenReturn(List.of(repository(60, NOW.minusSeconds(7200))));

        assertThat(scheduler.runOnce(NOW)).isEqualTo(1);
        assertThat(queued).singleElement().satisfies(scan -> {
            assertThat(scan.getRepoId()).isEqualTo(1L);
            assertThat(scan.getStatus()).isEqualTo("pending");
            assertThat(scan.getCreatedAt()).isEqualTo(NOW);
            // Copied here as on both manual paths: forgetting it on *one* of the three would make
            // targeting true "except for scheduled scans", which is false and silent.
            assertThat(scan.getRequiredAgentLabel()).isEqualTo("linux");
        });
        verify(repositories).stampScheduled(1L, NOW);
    }

    @Test
    @DisplayName("the stamp comes before the queue check, not after")
    void stampingPrecedesQueueing() {
        when(repositories.findAll()).thenReturn(List.of(repository(60, NOW.minusSeconds(7200))));

        scheduler.runOnce(NOW);

        // Stamping after would re-trigger the same target on every tick whenever a scan outlasts
        // an interval.
        InOrder order = inOrder(repositories, scans);
        order.verify(repositories).stampScheduled(1L, NOW);
        order.verify(scans).save(any());
    }

    @Test
    @DisplayName("a target already waiting is stamped but not queued twice")
    void doesNotStackScans() {
        when(repositories.findAll()).thenReturn(List.of(repository(60, NOW.minusSeconds(7200))));
        when(scans.countByStatusAndRepoId(anyString(), anyLong())).thenReturn(1L);

        assertThat(scheduler.runOnce(NOW)).isZero();
        verify(repositories).stampScheduled(1L, NOW);
        verify(scans, never()).save(any());
    }

    @Test
    @DisplayName("a target whose interval has not elapsed is left alone")
    void leavesAnUndueTargetAlone() {
        when(repositories.findAll()).thenReturn(List.of(repository(1440, NOW.minusSeconds(60))));

        assertThat(scheduler.runOnce(NOW)).isZero();
        verify(repositories, never()).stampScheduled(anyLong(), any());
    }

    @Test
    @DisplayName("an image scan carries \"n/a\" as its branch, like the manual trigger")
    void containersQueueWithNoBranch() {
        when(containers.findAll()).thenReturn(List.of(container()));

        assertThat(scheduler.runOnce(NOW)).isEqualTo(1);
        assertThat(queued).singleElement().satisfies(scan -> {
            assertThat(scan.getContainerId()).isEqualTo(4L);
            assertThat(scan.getBranch()).isEqualTo("n/a");
        });
    }

    @Test
    @DisplayName("a non-leader queues nothing")
    void onlyTheLeaderDispatches() {
        when(election.acquire(anyString(), anyString(), any())).thenReturn(false);
        when(repositories.findAll()).thenReturn(List.of(repository(60, NOW.minusSeconds(7200))));

        assertThat(scheduler.runOnce(NOW)).isZero();
        verify(repositories, never()).findAll();
    }

    @Test
    @DisplayName("an unreachable lease table skips the tick rather than assuming solitude")
    void failsClosed() {
        when(election.acquire(anyString(), anyString(), any())).thenThrow(new IllegalStateException("no database"));

        // Skipping a tick costs a minute of latency; wrongly believing itself leader costs a
        // duplicate scan of every due target.
        assertThat(scheduler.runOnce(NOW)).isZero();
    }

    @Test
    @DisplayName("one failing target does not take the others with it")
    void oneFailureDoesNotStopTheTick() {
        RepositoryEntity broken = repository(60, NOW.minusSeconds(7200));
        RepositoryEntity healthy = repository(60, NOW.minusSeconds(7200));
        healthy.setId(2L);
        when(repositories.findAll()).thenReturn(List.of(broken, healthy));
        when(repositories.stampScheduled(1L, NOW)).thenThrow(new IllegalStateException("constraint"));

        assertThat(scheduler.runOnce(NOW)).isEqualTo(1);
    }

    @Test
    @DisplayName("a cron expression wins over the interval")
    void cronTakesPrecedence() {
        RepositoryEntity daily = repository(1, NOW.minusSeconds(30));
        // A one-minute interval last scheduled thirty seconds ago says "due". The expression says
        // "not before three", and it is what the operator wrote down, so it decides.
        //
        // **This assertion used to prove nothing.** It read "0 2 * * *" against a parser that
        // required six fields, so the expression became `CronSchedule.NEVER` — never due, for the
        // wrong reason, and the precedence it claims to check was never exercised. Now that the
        // five-field form parses, the hour has to be one the window does not contain: due-ness is
        // measured from the last scheduled scan, not from now, so a daily 02:00 expression *is*
        // due at 02:00 when the last run was 01:59:30.
        daily.setScanCron("0 3 * * *");
        when(repositories.findAll()).thenReturn(List.of(daily));

        assertThat(scheduler.runOnce(NOW)).isZero();
    }

    @Test
    @DisplayName("a cron expression that has come round does dispatch")
    void cronCanBeDue() {
        RepositoryEntity daily = repository(1, NOW.minusSeconds(30));
        // The other half, and the one that catches a parser silently answering NEVER: an
        // expression whose moment falls inside the window has to fire. Without this, "the target
        // was never scanned" and "the schedule works" look identical.
        daily.setScanCron("0 2 * * *");
        when(repositories.findAll()).thenReturn(List.of(daily));

        assertThat(scheduler.runOnce(NOW)).isEqualTo(1);
    }

    @Test
    @DisplayName("an unusable expression stops the target rather than dropping it to the interval")
    void aBrokenCronDoesNotFallBackToTheInterval() {
        RepositoryEntity broken = repository(1, NOW.minusSeconds(7200));
        broken.setScanCron("not a cron expression");
        when(repositories.findAll()).thenReturn(List.of(broken));

        // Falling back would start a drifting schedule the operator never asked for.
        assertThat(scheduler.runOnce(NOW)).isZero();
    }

    private static RepositoryEntity repository(int intervalMinutes, Instant lastScheduled) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setId(1L);
        repository.setUrl("git@example.invalid:team/service.git");
        repository.setBranch("main");
        repository.setScanIntervalMinutes(intervalMinutes);
        repository.setLastScheduledScanAt(lastScheduled);
        repository.setRequiredAgentLabel("linux");
        return repository;
    }

    private static ContainerEntity container() {
        ContainerEntity container = new ContainerEntity();
        container.setId(4L);
        container.setImageName("team/service");
        container.setTag("1.4.0");
        container.setScanIntervalMinutes(60);
        container.setLastScheduledScanAt(NOW.minusSeconds(7200));
        return container;
    }
}
