package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("one turn of a remote agent")
class AgentLoopTest {

    private static final AgentProperties PROPERTIES = new AgentProperties(
            "https://vectispire.example", "zsk-token",
            Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(5), "docker", "1");

    private AgentProtocol protocol;
    private AgentLoop loop;

    @BeforeEach
    void wire() {
        protocol = mock(AgentProtocol.class);
        when(protocol.claim(any())).thenReturn(Optional.empty());
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

    @Test
    @DisplayName("a failed claim costs a turn, not a scan")
    void aFailedClaimIsNotAScan() {
        when(protocol.claim(any())).thenThrow(new IllegalStateException("connection refused"));
        loop = loopWith(task -> artifacts());

        assertThat(loop.runOnce()).isEqualTo(new AgentLoop.Result(0, 0, 0));
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
        when(protocol.claim(any())).thenReturn(Optional.of(new AgentProtocol.AssignedTask(
                7L,
                new ScanTask(
                        new ScanTask.Target.Repository("git@example.invalid:team/service.git", "main", "", null),
                        null,
                        Set.of(ScanTask.Step.DEPENDENCIES)))));
    }

    private AgentLoop loopWith(Function<ScanTask, ScanArtifacts> execute) {
        AgentLoop created = new AgentLoop(protocol, execute, PROPERTIES);
        return created;
    }

    private static ScanArtifacts artifacts() {
        return ScanArtifacts.builder().build(Duration.ofSeconds(3));
    }
}
