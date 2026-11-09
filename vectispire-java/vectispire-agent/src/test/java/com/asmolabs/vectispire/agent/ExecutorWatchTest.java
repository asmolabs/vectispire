package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.domain.agents.WorkerExecutors;
import com.asmolabs.vectispire.common.scanning.ContainerExecutor;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

@DisplayName("what the agent says about its executor, and when")
class ExecutorWatchTest {

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-11-01T10:00:00Z"));
    private final Clock clock = new Clock() {
        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    };

    private ContainerExecutor executor;
    private AgentProtocol protocol;

    @BeforeEach
    void wire() {
        executor = mock(ContainerExecutor.class);
        when(executor.whyUnavailable()).thenReturn(Optional.empty());
        when(executor.exportsImages()).thenReturn(true);
        protocol = mock(AgentProtocol.class);
        when(protocol.reportExecutors(any())).thenReturn(AgentProtocol.ExecutorReport.ACCEPTED);
    }

    private void later() {
        now.set(now.get().plus(ExecutorWatch.INTERVAL));
    }

    @Test
    @DisplayName("the hello carries the executor's answer: Docker scans both kinds, Kubernetes repositories only")
    void theHelloCarriesTheAnswer() {
        WorkerExecutors.Executor docker = new ExecutorWatch("docker", executor, clock).announced().executors().getFirst();
        assertThat(docker.kind()).isEqualTo("docker");
        assertThat(docker.available()).isTrue();
        assertThat(docker.targets()).containsExactly("repository", "container");
        assertThat(docker.detail()).isNull();

        when(executor.exportsImages()).thenReturn(false);
        when(executor.whyUnavailable()).thenReturn(Optional.of("The Kubernetes API did not list pods in scans: 403"));
        WorkerExecutors.Executor kubernetes =
                new ExecutorWatch("kubernetes", executor, clock).announced().executors().getFirst();
        assertThat(kubernetes.available()).isFalse();
        assertThat(kubernetes.targets()).containsExactly("repository");
        assertThat(kubernetes.detail()).contains("did not list pods");
    }

    @Test
    @DisplayName("an unchanged answer is not reported, and the executor is asked at most once per interval")
    void quietWhileNothingChanges() {
        ExecutorWatch watch = new ExecutorWatch("docker", executor, clock);
        watch.announced();

        watch.beforeClaim(protocol);
        watch.beforeClaim(protocol);
        later();
        watch.beforeClaim(protocol);

        verify(protocol, never()).reportExecutors(any());
        verify(executor, times(2)).whyUnavailable();
    }

    @Test
    @DisplayName("a change is reported once, and the way back too")
    void aChangeIsReported() {
        ExecutorWatch watch = new ExecutorWatch("docker", executor, clock);
        watch.announced();

        when(executor.whyUnavailable()).thenReturn(Optional.of("The Docker daemon did not answer a ping: refused"));
        later();
        watch.beforeClaim(protocol);
        later();
        watch.beforeClaim(protocol);
        when(executor.whyUnavailable()).thenReturn(Optional.empty());
        later();
        watch.beforeClaim(protocol);

        ArgumentCaptor<WorkerExecutors> reported = ArgumentCaptor.forClass(WorkerExecutors.class);
        verify(protocol, times(2)).reportExecutors(reported.capture());
        assertThat(reported.getAllValues().get(0).claimable()).isEmpty();
        assertThat(reported.getAllValues().get(1).claimable()).hasSize(2);
    }

    @Test
    @DisplayName("a report that did not arrive is sent again; an executor that throws counts as unavailable")
    void aLostReportIsSentAgain() {
        ExecutorWatch watch = new ExecutorWatch("docker", executor, clock);
        watch.announced();
        when(executor.whyUnavailable()).thenThrow(new IllegalStateException("socket gone"));
        when(protocol.reportExecutors(any()))
                .thenThrow(new IllegalStateException("The control plane is unreachable"))
                .thenReturn(AgentProtocol.ExecutorReport.FAILED)
                .thenReturn(AgentProtocol.ExecutorReport.ACCEPTED);

        for (int round = 0; round < 4; round++) {
            later();
            watch.beforeClaim(protocol);
        }

        ArgumentCaptor<WorkerExecutors> reported = ArgumentCaptor.forClass(WorkerExecutors.class);
        verify(protocol, times(3)).reportExecutors(reported.capture());
        assertThat(reported.getValue().executors().getFirst().detail()).contains("socket gone");
    }

    @Test
    @DisplayName("an older control plane (404) is not asked again; a refused key stops the agent")
    void notSupportedAndRefused() {
        ExecutorWatch watch = new ExecutorWatch("docker", executor, clock);
        watch.announced();
        when(executor.whyUnavailable()).thenReturn(Optional.of("down"));
        when(protocol.reportExecutors(any())).thenReturn(AgentProtocol.ExecutorReport.NOT_SUPPORTED);
        later();
        watch.beforeClaim(protocol);
        when(executor.whyUnavailable()).thenReturn(Optional.empty());
        later();
        watch.beforeClaim(protocol);
        verify(protocol, times(1)).reportExecutors(any());

        ExecutorWatch refused = new ExecutorWatch("docker", executor, clock);
        refused.announced();
        when(executor.whyUnavailable()).thenReturn(Optional.of("down"));
        when(protocol.reportExecutors(any())).thenThrow(new AgentProtocol.UnauthorizedException("API key refused."));
        later();
        assertThatThrownBy(() -> refused.beforeClaim(protocol)).isInstanceOf(AgentProtocol.UnauthorizedException.class);
    }

    @Test
    @DisplayName("the loop asks before each claim")
    void theLoopAsks() {
        ExecutorWatch watch = mock(ExecutorWatch.class);
        when(protocol.claim(any())).thenReturn(AgentProtocol.Claim.nothing());
        AgentProperties properties = new AgentProperties(
                "https://vectispire.example", "zsk-token",
                Duration.ofSeconds(1), Duration.ofSeconds(1), Duration.ofSeconds(5), "docker");

        new AgentLoop(protocol, task -> null, properties, 1, watch).runOnce();

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(watch, protocol);
        order.verify(watch).beforeClaim(protocol);
        order.verify(protocol).claim(any());
    }
}
