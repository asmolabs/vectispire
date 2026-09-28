package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import java.time.Duration;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

@DisplayName("one turn of a remote agent")
class AgentLoopTest {

    private static final AgentProperties PROPERTIES = new AgentProperties(
            "https://vectispire.example", "zsk-token",
            Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(5), "docker");

    private AgentProtocol protocol;
    private AgentLoop loop;

    @BeforeEach
    void wire() {
        protocol = mock(AgentProtocol.class);
        when(protocol.claim(any())).thenReturn(AgentProtocol.Claim.nothing());
        when(protocol.heartbeat(anyLong())).thenReturn(true);
        when(protocol.submit(anyLong(), any())).thenReturn(true);
    }

    @Test
    void doesNothingWhenTheQueueIsEmpty() {
        loop = loopWith(task -> artifacts());

        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 0, 0));
        verify(protocol, never()).submit(anyLong(), any());
    }

    @Test
    void runsAndSubmits() {
        assigned();
        loop = loopWith(task -> artifacts());

        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(1, 0, 0));
        verify(protocol).submit(7L, artifacts());
    }

    @Test
    @DisplayName("a failed execution hands back nothing at all")
    void aFailedRunSubmitsNothing() {
        assigned();
        loop = loopWith(task -> {
            throw new IllegalStateException("clone refused");
        });

        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 1, 0));
        // Posting an empty result would silently resolve the whole backlog of the types this
        // agent did not look at — absent versus empty, the distinction the system protects.
        verify(protocol, never()).submit(anyLong(), any());
    }

    /**
     * The silence this report replaced: the scan was dropped, its lease lapsed twenty minutes later,
     * an attempt was spent, and the reason stayed in this log.
     */
    @Test
    @DisplayName("a scan that could not run is reported with its reason, scrubbed of the task's key")
    void aFailedRunIsReported() {
        String key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----";
        AgentProtocol.AssignedTask assigned = new AgentProtocol.AssignedTask(
                7L, 2, new ScanTask(
                        new ScanTask.Target.Repository("git@example.invalid:team/service.git", "main", "", key),
                        null,
                        Set.of(ScanTask.Step.DEPENDENCIES)));
        when(protocol.claim(any())).thenReturn(new AgentProtocol.Claim(Optional.of(assigned), OptionalInt.empty()));
        when(protocol.reportFailure(any(), anyString())).thenReturn(AgentProtocol.FailureReported.RETRIED);
        loop = loopWith(task -> {
            throw new IllegalStateException("The host key of ssh://git@gitea/team/app.git changed; key line "
                    + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ, token zsk-token");
        });

        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 1, 0));
        ArgumentCaptor<String> reason = ArgumentCaptor.forClass(String.class);
        verify(protocol).reportFailure(org.mockito.ArgumentMatchers.eq(assigned), reason.capture());
        assertThat(reason.getValue())
                .contains("The host key of ssh://git@gitea/team/app.git changed")
                .doesNotContain("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ")
                .doesNotContain("zsk-token");
        verify(protocol, never()).submit(anyLong(), any());
    }

    @Test
    @DisplayName("a control plane without the report, or a report that does not arrive, leaves the scan to its lease")
    void anUnreportedFailureFallsBackToTheLease() {
        assigned();
        loop = loopWith(task -> {
            throw new IllegalStateException("clone refused");
        });

        when(protocol.reportFailure(any(), anyString())).thenReturn(AgentProtocol.FailureReported.NOT_SUPPORTED);
        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 1, 0));

        when(protocol.reportFailure(any(), anyString())).thenThrow(new IllegalStateException("connection reset"));
        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 1, 0));
        verify(protocol, never()).submit(anyLong(), any());
    }

    @Test
    @DisplayName("a claimed task that cannot be used is reported, and costs the loop a turn, not the agent")
    void anUnusableTaskIsReported() {
        AgentProtocol.AssignedTask received = task(9L);
        when(protocol.claim(any())).thenThrow(new AgentProtocol.UnusableTaskException(
                received, "The sealed deployment key could not be opened."));
        when(protocol.reportFailure(any(), anyString())).thenReturn(AgentProtocol.FailureReported.RETRIED);
        loop = loopWith(task -> artifacts());

        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 0, 0));
        verify(protocol).reportFailure(received, "The sealed deployment key could not be opened.");
    }

    @Test
    @DisplayName("a failed claim costs a turn, not a scan")
    void aFailedClaimIsNotAScan() {
        when(protocol.claim(any())).thenThrow(new IllegalStateException("connection refused"));
        loop = loopWith(task -> artifacts());

        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 0, 0));
    }

    @Test
    @DisplayName("a refused key on a claim stops the agent instead of being retried as a hiccup")
    void aRefusedKeyIsNotAFailedClaim() {
        // Caught as a failed claim, a revoked key was retried every ten seconds for ever, and the
        // agent's log said "could not claim" — a network problem, to whoever read it.
        when(protocol.claim(any())).thenThrow(new AgentProtocol.UnauthorizedException("API key refused."));
        loop = loopWith(task -> artifacts());

        org.assertj.core.api.Assertions.assertThatThrownBy(loop::runOnce)
                .isInstanceOf(AgentProtocol.UnauthorizedException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(loop::serve)
                .isInstanceOf(AgentProtocol.UnauthorizedException.class);
    }

    @Test
    @DisplayName("a lease taken over during the run discards the result")
    void aStolenLeaseDiscardsTheResult() {
        assigned();
        when(protocol.submit(anyLong(), any())).thenReturn(false);
        loop = loopWith(task -> artifacts());

        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 0, 1));
    }

    @Test
    @DisplayName("work done but not delivered counts as failed, and is not retried here")
    void anUndeliveredResultIsNotRetried() {
        assigned();
        when(protocol.submit(anyLong(), any())).thenThrow(new IllegalStateException("gateway timeout"));
        loop = loopWith(task -> artifacts());

        // Retrying the upload would keep an agent busy on a result whose lease is lapsing anyway.
        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 1, 0));
    }

    private void assigned() {
        when(protocol.claim(any())).thenReturn(new AgentProtocol.Claim(Optional.of(task(7L)), OptionalInt.empty()));
    }

    private static AgentProtocol.AssignedTask task(long scanId) {
        return new AgentProtocol.AssignedTask(
                scanId,
                new ScanTask(
                        new ScanTask.Target.Repository("git@example.invalid:team/service.git", "main", "", null),
                        null,
                        Set.of(ScanTask.Step.DEPENDENCIES)));
    }

    private AgentLoop loopWith(Function<ScanTask, ScanArtifacts> execute) {
        AgentLoop created = new AgentLoop(protocol, execute, PROPERTIES);
        return created;
    }

    private static ScanArtifacts artifacts() {
        return ScanArtifacts.builder().build(Duration.ofSeconds(3));
    }
}
