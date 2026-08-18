package com.asmolabs.zanshin.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.zanshin.core.persistence.LeaderLeaseEntity;
import com.asmolabs.zanshin.core.repositories.LeaderLeases;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

@DisplayName("the lease that makes a job single-owner")
class LeaderElectionTest {

    private static final Instant NOW = Instant.parse("2026-08-18T02:00:00Z");
    private static final Duration LEASE = Duration.ofSeconds(180);
    private static final String ME = "instance-a";
    private static final String THEM = "instance-b";

    private LeaderLeases leases;
    private LeaderElection election;

    @BeforeEach
    void wire() {
        leases = mock(LeaderLeases.class);
        election = new LeaderElection(leases, new LeaderProperties(LEASE), Clock.fixed(NOW, ZoneOffset.UTC));
        when(leases.findById(anyString())).thenReturn(Optional.empty());
    }

    @Test
    @DisplayName("nobody has ever held it: insert, and the primary key arbitrates")
    void firstAcquisitionInserts() {
        when(leases.insertNew(anyString(), anyString(), any(), any(), any())).thenReturn(1);

        assertThat(election.acquire("scheduler", ME, NOW)).isTrue();
        verify(leases).insertNew("scheduler", ME, NOW, NOW.plus(LEASE), NOW);
    }

    @Test
    @DisplayName("two instances starting together: the loser catches the violation and waits")
    void theLoserOfTheInsertRaceBacksOff() {
        when(leases.insertNew(anyString(), anyString(), any(), any(), any()))
                .thenThrow(new DataIntegrityViolationException("duplicate key"));

        assertThat(election.acquire("scheduler", ME, NOW)).isFalse();
    }

    @Test
    @DisplayName("we already hold it: renew, which is what keeps the leader stable")
    void renewalKeepsTheLease() {
        when(leases.findById("scheduler")).thenReturn(Optional.of(lease(ME, NOW.plusSeconds(60))));
        when(leases.renew(anyString(), anyString(), any(), any())).thenReturn(1);

        assertThat(election.acquire("scheduler", ME, NOW)).isTrue();
        // A leader that had to win again every tick would move the work around the fleet for no
        // reason.
        verify(leases).renew("scheduler", ME, NOW.plus(LEASE), NOW);
        verify(leases, never()).takeOver(anyString(), anyString(), any(), any(), anyString(), any());
    }

    @Test
    @DisplayName("somebody else holds a live lease: we lose without touching the row")
    void aLiveLeaseIsNotStolen() {
        when(leases.findById("scheduler")).thenReturn(Optional.of(lease(THEM, NOW.plusSeconds(60))));

        assertThat(election.acquire("scheduler", ME, NOW)).isFalse();
        verify(leases, never()).takeOver(anyString(), anyString(), any(), any(), anyString(), any());
        verify(leases, never()).renew(anyString(), anyString(), any(), any());
    }

    @Test
    @DisplayName("an expired lease is taken over, conditioned on what was read")
    void anExpiredLeaseIsTakenOver() {
        Instant expiry = NOW.minusSeconds(1);
        when(leases.findById("scheduler")).thenReturn(Optional.of(lease(THEM, expiry)));
        when(leases.takeOver(anyString(), anyString(), any(), any(), anyString(), any())).thenReturn(1);

        assertThat(election.acquire("scheduler", ME, NOW)).isTrue();
        verify(leases).takeOver("scheduler", ME, NOW.plus(LEASE), NOW, THEM, expiry);
    }

    @Test
    @DisplayName("losing the take-over race means losing, not stealing")
    void aRacedTakeOverAffectsNothing() {
        when(leases.findById("scheduler")).thenReturn(Optional.of(lease(THEM, NOW.minusSeconds(1))));
        // Another instance got there between our read and our update, so the conditions no
        // longer match and the statement changes nothing.
        when(leases.takeOver(anyString(), anyString(), any(), any(), anyString(), any())).thenReturn(0);

        assertThat(election.acquire("scheduler", ME, NOW)).isFalse();
    }

    @Test
    @DisplayName("a lease with no expiry counts as expired")
    void aLeaseThatNeverExpiresIsNoLease() {
        when(leases.findById("scheduler")).thenReturn(Optional.of(lease(THEM, null)));
        when(leases.takeOver(anyString(), anyString(), any(), any(), anyString(), any())).thenReturn(1);

        assertThat(election.acquire("scheduler", ME, NOW)).isTrue();
    }

    @Test
    void reportsWhoHoldsItForTheScreen() {
        when(leases.findById("scheduler")).thenReturn(Optional.of(lease(THEM, NOW.plusSeconds(60))));

        assertThat(election.currentHolder("scheduler", NOW)).contains(THEM);
        assertThat(election.isLeader("scheduler", ME, NOW)).isFalse();
        assertThat(election.isLeader("scheduler", THEM, NOW)).isTrue();
    }

    @Test
    @DisplayName("a stale lease has no holder, however the row reads")
    void anExpiredLeaseHasNoHolder() {
        when(leases.findById("scheduler")).thenReturn(Optional.of(lease(THEM, NOW.minusSeconds(1))));

        assertThat(election.currentHolder("scheduler", NOW)).isEmpty();
    }

    @Test
    void releasingIsConditionedOnStillHoldingIt() {
        when(leases.release("scheduler", ME, NOW)).thenReturn(1);

        assertThat(election.release("scheduler", ME)).isTrue();
        assertThat(election.release("scheduler", THEM)).isFalse();
    }

    private static LeaderLeaseEntity lease(String holder, Instant expiresAt) {
        LeaderLeaseEntity lease = new LeaderLeaseEntity();
        lease.setName("scheduler");
        lease.setHolder(holder);
        lease.setAcquiredAt(NOW.minusSeconds(300));
        lease.setExpiresAt(expiresAt);
        lease.setUpdatedAt(NOW.minusSeconds(300));
        return lease;
    }
}
